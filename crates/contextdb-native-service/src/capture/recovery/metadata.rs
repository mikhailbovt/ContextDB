//! Body-free acceptance and immutable attribution for projected causal sources.

use super::*;
use crate::raw_index::{IndexedOriginal, budget_error};
use contextdb_core::RawSource;
use contextdb_recall::QueryBudget;

impl NativeService {
    /// The caller must currently authorize the source and all custody inputs
    /// before reading its derived document. This verifies immutable attribution,
    /// not permission, and never loads the original payload.
    pub(crate) fn verify_projected_causal_metadata<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        document: &IndexedOriginal,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let (record, encoded_bytes) =
            self.causal_capture_record(snapshot, document.source.event_id, budget)?;
        let recovery = record.recovery.as_ref().ok_or_else(|| {
            ServiceError::new(
                ErrorCode::Unsupported,
                "body-free causal attribution requires retained capture recovery",
                false,
            )
        })?;
        budget
            .charge(1, encoded_bytes as u64 * 2 + 8192)
            .map_err(budget_error)?;
        crate::budgeted::metadata(snapshot, budget, |reader| {
            self.verify_recovery_features(reader, recovery)
        })?;
        self.verify_causal_capture_record(snapshot, workspace, &record, encoded_bytes, budget)?;
        if record.receipt.event_id != document.source.event_id
            || record.receipt.workspace_commit != document.commit
            || record.receipt.event_digest != document.event_digest
            || record.receipt.payload_digest != document.source.payload_digest
        {
            return Err(integrity(
                "causal document differs from accepted capture version",
            ));
        }
        bind_source(recovery, &document.source, &document.parents, budget)
    }

    /// Authenticate a bounded outbox locator without opening its original body.
    /// Used only to report that the projected adjacency prefix is incomplete.
    pub(crate) fn verify_causal_capture_work<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        work: &CaptureWork,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let (record, encoded_bytes) =
            self.causal_capture_record(snapshot, work.event_id, budget)?;
        let recovery = record.recovery.as_ref().ok_or_else(|| {
            ServiceError::new(
                ErrorCode::Unsupported,
                "body-free causal lag proof requires retained capture recovery",
                false,
            )
        })?;
        budget
            .charge(1, encoded_bytes as u64 * 2 + 8192)
            .map_err(budget_error)?;
        crate::budgeted::metadata(snapshot, budget, |reader| {
            self.verify_recovery_features(reader, recovery)
        })?;
        budget
            .charge(1, encoded_bytes as u64 * 2 + 1024)
            .map_err(budget_error)?;
        if record.work()? != *work {
            return Err(integrity(
                "causal outbox differs from accepted capture controls",
            ));
        }
        self.verify_causal_capture_record(snapshot, workspace, &record, encoded_bytes, budget)
    }

    fn causal_capture_record<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(CaptureRecord, usize)> {
        let bytes = crate::budgeted::read_value(
            snapshot,
            &self.keyspaces.continuous,
            &record_key(id),
            MAX_CAPTURE_CONTROL_BYTES,
            budget,
        )?
        .ok_or_else(|| integrity("causal capture control metadata is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        let record = decode(&bytes, "bounded causal capture control metadata")?;
        Ok((record, bytes.len()))
    }

    fn verify_causal_capture_record<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        record: &CaptureRecord,
        encoded_bytes: usize,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        // Reserve before cloning/encoding controls. The recovery cap is already
        // checked by the bounded record reader, including all dependency sets.
        budget
            .charge(1, encoded_bytes as u64 * 4 + 8192)
            .map_err(budget_error)?;
        let work = record.work()?;
        let receipt = &record.receipt;
        let mut unsigned = receipt.clone();
        unsigned.token.clear();
        if receipt.token
            != keyed_token(
                &self.token_key,
                b"contextdb/capture-receipt/v1\0",
                &encode(&unsigned)?,
            )
            || receipt.domain != NATIVE_CAPTURE_DOMAIN
            || receipt.database_id != self.database_id
            || digest_bytes(receipt.workspace_id.to_string().as_bytes()) != workspace
            || receipt.durability != CaptureDurability::Sync
        {
            return Err(integrity("causal source receipt authentication differs"));
        }
        let (global, _) = crate::budgeted::metadata(snapshot, budget, |reader| {
            self.select_snapshot(
                reader,
                &receipt.workspace_id.to_string(),
                Some(receipt.workspace_commit),
            )
        })?;
        let bytes = crate::budgeted::read_value(
            snapshot,
            &self.keyspaces.events,
            &global.to_be_bytes(),
            MAX_CAPTURE_CONTROL_BYTES,
            budget,
        )?
        .ok_or_else(|| integrity("causal source accepted publication is absent"))?;
        budget
            .charge(1, bytes.len() as u64 * 3)
            .map_err(budget_error)?;
        let event: crate::StoredEvent = decode(&bytes, "causal source accepted publication")?;
        if event.operation != "capture"
            || event.schema_version != SCHEMA_VERSION
            || event.global_commit != global
            || event.workspace_commit != receipt.workspace_commit
            || event.workspace_digest != workspace
            || event.accepted_original.as_ref() != Some(&work)
            || event.event_digest != crate::event_digest(&event)?
            || event.response_digest != digest_bytes(&encode(receipt)?)
        {
            return Err(integrity("causal source has no matching accepted capture"));
        }
        Ok(())
    }
}

fn bind_source(
    recovery: &CaptureRecovery,
    source: &RawSource,
    parents: &BTreeSet<ObservationId>,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    let version_bytes = source.source_version.as_ref().map_or(0, String::len);
    if version_bytes > 2048 || recovery.parent_event_ids.len() > 64 || parents.len() > 65 {
        return Err(integrity("causal source metadata exceeds captured bounds"));
    }
    budget
        .charge(
            version_bytes as u64 + parents.len() as u64 * 4 + 1,
            version_bytes as u64,
        )
        .map_err(budget_error)?;
    let omission = match recovery.payload.shape {
        PayloadShape::Omitted { reason } => Some(reason),
        _ => None,
    };
    let independent = recovery.kind != EventKind::ModelRequested
        && !matches!(recovery.payload.shape, PayloadShape::Assembly);
    if source.source_id != recovery.source_id
        || source.source_version.as_deref().map(text_digest) != recovery.source_version_digest
        || source.session_id != recovery.session_id
        || source.kind != recovery.kind
        || source.role != recovery.role
        || source.recorded_at != recovery.recorded_at
        || source.supersedes_event_id != recovery.supersedes_event_id
        || source.payload_digest != recovery.payload.digest
        || source.byte_length != recovery.payload.bytes
        || source.omission != omission
        || source.coverage != recovery.coverage
        || source.upstream_truncated != recovery.upstream_truncated
        || source.independent_source != independent
        || recovery
            .parent_event_ids
            .iter()
            .any(|id| !parents.contains(id))
        || recovery
            .supersedes_event_id
            .is_some_and(|id| !parents.contains(&id))
        || parents.iter().any(|id| {
            !recovery.parent_event_ids.contains(id) && Some(*id) != recovery.supersedes_event_id
        })
    {
        return Err(integrity(
            "causal projected source differs from immutable capture metadata",
        ));
    }
    Ok(())
}
