//! Reconstruct exact pruning progress; unexplained holes never become deletion.

use std::collections::BTreeMap;

use super::*;

impl NativeService {
    // A missing marker must not restart an accepted job, even for an empty
    // original or when all erased chunks have been resurrected together.
    pub(super) fn require_new_payload_pruning<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ContentBlockId,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> ServiceResult<()> {
        let mut after = None;
        loop {
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.events,
                    contextdb_storage::ScanPageRequest {
                        prefix: b"",
                        start_after: after.as_deref(),
                        max_entries: 256,
                        max_bytes: 1024 * 1024,
                    },
                )
                .map_err(storage_error)?;
            for row in page.entries {
                budget
                    .charge(1, row.value.len() as u64)
                    .map_err(crate::raw_index::budget_error)?;
                let event: crate::StoredEvent = decode(&row.value, "prior payload pruning")?;
                if event
                    .accepted_payload_pruning
                    .as_ref()
                    .is_some_and(|publication| publication.state.reference.block_id == id)
                    || (event.operation == "payload_prune"
                        && event.accepted_payload_pruning.is_none())
                {
                    return Err(integrity(
                        "payload pruning journal exists without its retained progress",
                    ));
                }
                after = Some(row.key);
            }
            if page.continuation.is_none() {
                break;
            }
        }
        Ok(())
    }

    pub(in super::super) fn verify_payload_header_control<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        header: &PayloadHeader,
    ) -> ServiceResult<()> {
        let retry: crate::StoredIdempotency = decode(
            &snapshot
                .get(
                    &self.keyspaces.idempotency,
                    header.idempotency_digest.as_bytes(),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("payload retry binding is absent"))?,
            "payload retry",
        )?;
        let receipt: PayloadReceipt = decode(&retry.response_bytes, "payload receipt")?;
        let event: crate::StoredEvent = decode(
            &snapshot
                .get(
                    &self.keyspaces.events,
                    &header.accepted_global_commit.to_be_bytes(),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("payload staging journal is absent"))?,
            "payload staging journal",
        )?;
        if retry.schema_version != crate::SCHEMA_VERSION
            || retry.operation != "stage_payload"
            || retry.response_bytes != encode(&receipt)?
            || retry.response_digest != digest_bytes(&retry.response_bytes)
            || receipt.database_id != self.database_id
            || receipt.reference != header.reference
            || receipt.durability != CaptureDurability::Sync
            || event.schema_version != crate::SCHEMA_VERSION
            || event.operation != "stage_payload"
            || event.global_commit != header.accepted_global_commit
            || event.workspace_digest != digest_bytes(header.access.workspace_id.as_bytes())
            || event.request_digest != retry.request_digest
            || event.response_digest != retry.response_digest
            || event.accepted_payload.as_ref() != Some(&header.reference)
            || event.event_digest != event_digest(&event)?
        {
            return Err(integrity(
                "payload header has no exact accepted staging control",
            ));
        }
        Ok(())
    }

    pub(super) fn verified_payload_pruning<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        header: &PayloadHeader,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> ServiceResult<Option<PayloadPruningState>> {
        let Some(state) = self.payload_pruning_state(snapshot, header.reference.block_id)? else {
            return Ok(None);
        };
        budget
            .charge(1, encode(&state)?.len() as u64)
            .map_err(crate::raw_index::budget_error)?;
        self.verify_payload_pruning_binding(snapshot, header, &state, budget)?;
        let (mut global, mut publication) = self.read_payload_pruning_publication(
            snapshot,
            &header.access.workspace_id,
            state.workspace_commit,
            budget,
        )?;
        if publication.state != state {
            return Err(integrity(
                "payload pruning marker differs from its publication",
            ));
        }
        for _ in 0..header.chunks.max(1) {
            if let Some(previous) = publication.previous_commit {
                let (previous_global, previous_publication) = self
                    .read_payload_pruning_publication(
                        snapshot,
                        &header.access.workspace_id,
                        previous,
                        budget,
                    )?;
                validate_transition(Some(&previous_publication.state), &publication, header)?;
                if previous_global >= global {
                    return Err(integrity("payload pruning publication order differs"));
                }
                global = previous_global;
                publication = previous_publication;
            } else {
                validate_transition(None, &publication, header)?;
                if header.accepted_global_commit >= global {
                    return Err(integrity("payload pruning precedes staging"));
                }
                for index in 0..state.through {
                    if let Some(bytes) = snapshot
                        .get(
                            &self.keyspaces.continuous,
                            &chunk_key(state.reference.block_id, index),
                        )
                        .map_err(storage_error)?
                    {
                        budget
                            .charge(1, bytes.len() as u64)
                            .map_err(crate::raw_index::budget_error)?;
                        return Err(integrity("removed payload chunk was resurrected"));
                    }
                    budget
                        .charge(1, 0)
                        .map_err(crate::raw_index::budget_error)?;
                }
                return Ok(Some(state));
            }
        }
        Err(integrity("payload pruning chain exceeds its chunk bound"))
    }

    pub(in super::super) fn verify_payload_pruning_records<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<BTreeMap<ContentBlockId, u32>> {
        let mut expected: BTreeMap<ContentBlockId, PayloadPruningState> = BTreeMap::new();
        for row in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: crate::StoredEvent = decode(&row.value, "payload pruning journal")?;
            let Some(publication) = &event.accepted_payload_pruning else {
                if event.operation == "payload_prune" {
                    return Err(integrity("payload pruning journal lost its reference"));
                }
                continue;
            };
            let header = self.payload_header(snapshot, publication.state.reference.block_id)?;
            checked_publication(&event, &header.access.workspace_id)?;
            validate_transition(
                expected.get(&header.reference.block_id),
                publication,
                &header,
            )?;
            if header.accepted_global_commit >= event.global_commit {
                return Err(integrity("payload pruning precedes its original"));
            }
            expected.insert(header.reference.block_id, publication.state.clone());
        }
        let rows = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"payload/pruned/")
            .map_err(storage_error)?;
        if rows.len() != expected.len() {
            return Err(integrity(
                "payload pruning marker family differs from accepted history",
            ));
        }
        let mut budget = retention::audit_budget();
        let mut result = BTreeMap::new();
        for state in expected.into_values() {
            if snapshot
                .get(
                    &self.keyspaces.continuous,
                    &pruning_key(state.reference.block_id),
                )
                .map_err(storage_error)?
                != Some(encode(&state)?)
            {
                return Err(integrity(
                    "payload pruning marker differs from accepted progress",
                ));
            }
            let header = self.payload_header(snapshot, state.reference.block_id)?;
            self.verify_payload_pruning_binding(snapshot, &header, &state, &mut budget)?;
            result.insert(state.reference.block_id, state.through);
        }
        Ok(result)
    }

    fn verify_payload_pruning_binding<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        header: &PayloadHeader,
        state: &PayloadPruningState,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> ServiceResult<()> {
        let manifest: Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("payload pruning format is absent"))?,
            "payload pruning format",
        )?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("payload pruning authority is absent"))?;
        if !manifest.features.contains(PAYLOAD_PRUNING_FEATURE)
            || state.reference != header.reference
            || state.header_digest != raw_digest(&encode(header)?)
            || state.through > header.chunks
            || ledger.removal_payload(
                &digest_bytes(header.access.workspace_id.as_bytes()),
                &state.request,
                state.reference.block_id,
                budget,
            )? != header.reference
        {
            return Err(integrity(
                "payload pruning control or retained membership differs",
            ));
        }
        self.verify_payload_header_control(snapshot, header)
    }

    fn read_payload_pruning_publication<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        commit: u64,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> ServiceResult<(u64, PayloadPruningPublication)> {
        let (global, _) = self.select_snapshot(snapshot, workspace, Some(commit))?;
        let bytes = snapshot
            .get(&self.keyspaces.events, &global.to_be_bytes())
            .map_err(storage_error)?
            .ok_or_else(|| integrity("payload pruning publication is absent"))?;
        budget
            .charge(1, bytes.len() as u64)
            .map_err(crate::raw_index::budget_error)?;
        let event: crate::StoredEvent = decode(&bytes, "payload pruning publication")?;
        if event.global_commit != global || event.workspace_commit != commit {
            return Err(integrity("payload pruning publication mapping differs"));
        }
        Ok((global, checked_publication(&event, workspace)?.clone()))
    }
}

fn checked_publication<'a>(
    event: &'a crate::StoredEvent,
    workspace: &str,
) -> ServiceResult<&'a PayloadPruningPublication> {
    let publication = event
        .accepted_payload_pruning
        .as_ref()
        .ok_or_else(|| integrity("payload pruning reference is absent"))?;
    if event.operation != "payload_prune"
        || event.schema_version != crate::SCHEMA_VERSION
        || event.workspace_digest != digest_bytes(workspace.as_bytes())
        || event.workspace_commit != publication.state.workspace_commit
        || event.request_digest != publication_digest(&event.workspace_digest, publication)?
        || event.response_digest != digest_bytes(&encode(publication)?)
        || event.event_digest != event_digest(event)?
    {
        return Err(integrity("payload pruning journal binding differs"));
    }
    Ok(publication)
}

fn validate_transition(
    previous: Option<&PayloadPruningState>,
    publication: &PayloadPruningPublication,
    header: &PayloadHeader,
) -> ServiceResult<()> {
    let state = &publication.state;
    if state.reference != header.reference
        || state.header_digest != raw_digest(&encode(header)?)
        || state.started_commit == 0
        || state.started_commit > state.workspace_commit
        || state.through > header.chunks
        || state.through < publication.from
        || state.through - publication.from > MAX_BATCH
        || (state.through == publication.from && header.chunks != 0)
    {
        return Err(integrity(
            "payload pruning progress exceeds its original bounds",
        ));
    }
    if let Some(previous) = previous {
        if publication.previous_commit != Some(previous.workspace_commit)
            || publication.from != previous.through
            || state.workspace_commit <= previous.workspace_commit
            || previous.through == header.chunks
            || state.request != previous.request
            || state.started_commit != previous.started_commit
            || state.reference != previous.reference
            || state.header_digest != previous.header_digest
        {
            return Err(integrity(
                "payload pruning has a gap or changed original control",
            ));
        }
    } else if publication.previous_commit.is_some()
        || publication.from != 0
        || state.started_commit != state.workspace_commit
    {
        return Err(integrity("payload pruning start is missing or invalid"));
    }
    Ok(())
}
