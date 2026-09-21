//! Explicit, bounded chunk removal while retaining immutable staging controls.

#[cfg(test)]
mod tests;
mod verify;

use crate::{
    NativeRemovalRequestReceipt, digest_bytes, event_digest, retention,
    suppression::RemovalCheckpoint,
};

use super::*;

pub(crate) const PAYLOAD_PRUNING_FEATURE: &str = "continuous-payload-pruning-v1";
const MAX_BATCH: u32 = 32;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadPruningState {
    request: RemovalCheckpoint,
    reference: OriginalPayloadRef,
    header_digest: ContentDigest,
    started_commit: u64,
    workspace_commit: u64,
    through: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PayloadPruningPublication {
    previous_commit: Option<u64>,
    from: u32,
    state: PayloadPruningState,
}

impl PayloadPruningPublication {
    pub(crate) fn removal_request(&self) -> &RemovalCheckpoint {
        &self.state.request
    }
}

/// Logical chunk removal only. Physical pages, keys and external copies remain
/// distinct obligations. `complete` applies only to this local block's chunks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePayloadPruningProgress {
    /// Exact staged block being cleaned.
    pub block_id: ContentBlockId,
    /// Native workspace publication retaining the current progress.
    pub workspace_commit: u64,
    /// Contiguous chunk prefix removed with durable evidence.
    pub removed_chunks: u32,
    /// Original number of chunks, preserved by the staging header.
    pub total_chunks: u32,
    /// Every chunk of this local block has been logically removed.
    pub complete: bool,
}

impl NativeService {
    /// Prune up to 32 chunks (8 MiB) of one selected block per publication.
    /// First use verifies its complete original (at most 64 MiB), fresh ownership
    /// and all affected primary tombstones outside the native publication lock.
    /// Later calls verify the accepted progress chain and the next chunk batch.
    /// Shared blocks with an independent captured owner cannot start cleanup.
    pub fn prune_original_payload(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &NativeRemovalRequestReceipt,
        block_id: ContentBlockId,
        max_chunks: u32,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> ServiceResult<NativePayloadPruningProgress> {
        require_capability(context, Capability::Admin)?;
        if !(1..=MAX_BATCH).contains(&max_chunks) {
            return Err(invalid("payload pruning batch must contain 1..32 chunks"));
        }
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| invalid("payload pruning requires retained authority"))?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let request = RemovalCheckpoint {
            sequence: receipt.sequence,
            digest: receipt.digest.clone(),
        };
        let intent = ledger.retained_removal_intent(&workspace, &request)?;
        if retention::removal_receipt(ledger, &request, &intent) != *receipt {
            return Err(invalid("payload pruning request receipt differs"));
        }
        let selected = ledger.removal_payload(&workspace, &request, block_id, budget)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let world = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        let header = self.payload_header(&snapshot, block_id)?;
        budget
            .charge(1, encode(&header)?.len() as u64)
            .map_err(crate::raw_index::budget_error)?;
        if header.reference != selected
            || header.access.workspace_id != context.request.workspace_id
        {
            return Err(integrity(
                "pruning payload differs from its retained selection",
            ));
        }
        self.verify_payload_header_control(&snapshot, &header)?;
        let previous = self.verified_payload_pruning(&snapshot, &header, budget)?;
        let from = previous.as_ref().map_or(0, |state| state.through);
        if let Some(state) = &previous
            && from == header.chunks
        {
            return Ok(progress(state, header.chunks));
        }
        if previous.is_none() {
            let closure = self.inspect_original_deletion(context, &receipt.roots, budget)?;
            if closure.workspace_commit != world.watermarks.journal {
                return Err(stale());
            }
            self.require_new_payload_pruning(&snapshot, block_id, budget)?;
            if !closure.payloads.contains(&selected) {
                return Err(invalid(
                    "payload has an independent owner or is outside the current deletion closure",
                ));
            }
            for source in &closure.sources {
                if ledger.removal_source(&workspace, &request, source.receipt.event_id, budget)?
                    != *source
                    || self.verify_pruned_source(&snapshot, source.receipt.event_id, budget)?
                        != Some(source.control_digest)
                {
                    return Err(invalid(
                        "prune every affected primary original before its staged blocks",
                    ));
                }
            }
            budget
                .charge(header.chunks as u64, header.reference.byte_length)
                .map_err(crate::raw_index::budget_error)?;
            self.payload_bytes(&snapshot, &header)?;
        }
        let through = from.saturating_add(max_chunks).min(header.chunks);
        if previous.is_some() {
            for index in from..through {
                self.verified_pruning_chunk(&snapshot, &header, index, budget)?;
            }
        }
        #[cfg(test)]
        BEFORE_PUBLICATION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if self.workspace_state(&tx, &context.request.workspace_id)? != world
            || self.payload_pruning_state(&tx, block_id)? != previous
        {
            return Err(stale());
        }
        let frame = self.begin_frame(&tx, &context.request.workspace_id, false)?;
        let state = PayloadPruningState {
            request: previous
                .as_ref()
                .map_or(request, |state| state.request.clone()),
            reference: selected,
            header_digest: raw_digest(&encode(&header)?),
            started_commit: previous
                .as_ref()
                .map_or(frame.state.watermarks.journal, |state| state.started_commit),
            workspace_commit: frame.state.watermarks.journal,
            through,
        };
        let publication = PayloadPruningPublication {
            previous_commit: previous.as_ref().map(|state| state.workspace_commit),
            from,
            state: state.clone(),
        };
        for index in from..through {
            tx.delete(&self.keyspaces.continuous, chunk_key(block_id, index))
                .map_err(storage_error)?;
        }
        tx.put(
            &self.keyspaces.continuous,
            pruning_key(block_id),
            encode(&state)?,
        )
        .map_err(storage_error)?;
        self.enable_capture_extension(&mut tx, PAYLOAD_PRUNING_FEATURE)?;
        let digest = publication_digest(&workspace, &publication)?;
        self.finish_frame(
            &mut tx,
            &frame,
            "payload_prune",
            digest.as_bytes(),
            &digest,
            &publication,
        )?;
        budget.check().map_err(crate::raw_index::budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(progress(&state, header.chunks))
    }

    pub(super) fn require_payload_unpruned<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ContentBlockId,
    ) -> ServiceResult<()> {
        if snapshot
            .get(&self.keyspaces.continuous, &pruning_key(id))
            .map_err(storage_error)?
            .is_some()
        {
            return Err(permission_denied());
        }
        Ok(())
    }

    fn payload_pruning_state<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ContentBlockId,
    ) -> ServiceResult<Option<PayloadPruningState>> {
        snapshot
            .get(&self.keyspaces.continuous, &pruning_key(id))
            .map_err(storage_error)?
            .map(|bytes| decode(&bytes, "payload pruning state"))
            .transpose()
    }

    pub(super) fn verified_pruning_chunk<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        header: &PayloadHeader,
        index: u32,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> ServiceResult<()> {
        let chunk = snapshot
            .get(
                &self.keyspaces.continuous,
                &chunk_key(header.reference.block_id, index),
            )
            .map_err(storage_error)?
            .ok_or_else(|| integrity("unpruned payload chunk is absent"))?;
        budget
            .charge(1, chunk.len() as u64)
            .map_err(crate::raw_index::budget_error)?;
        let remaining = header
            .reference
            .byte_length
            .saturating_sub(index as u64 * CHUNK_BYTES as u64);
        if chunk.len() as u64 != remaining.min(CHUNK_BYTES as u64)
            || header.chunk_digests.get(index as usize) != Some(&raw_digest(&chunk))
        {
            return Err(integrity(
                "unpruned payload chunk differs from its immutable manifest",
            ));
        }
        Ok(())
    }
}

pub(super) fn pruning_key(id: ContentBlockId) -> Vec<u8> {
    format!("payload/pruned/{id}").into_bytes()
}
fn publication_digest(
    workspace: &str,
    publication: &PayloadPruningPublication,
) -> ServiceResult<String> {
    canonical_digest(&("native/payload_prune/v1", workspace, publication))
}
fn progress(state: &PayloadPruningState, chunks: u32) -> NativePayloadPruningProgress {
    NativePayloadPruningProgress {
        block_id: state.reference.block_id,
        workspace_commit: state.workspace_commit,
        removed_chunks: state.through,
        total_chunks: chunks,
        complete: state.through == chunks,
    }
}
fn stale() -> ServiceError {
    ServiceError::new(
        ErrorCode::IndexTooStale,
        "payload pruning history changed; retry the remaining work",
        true,
    )
}

#[cfg(test)]
thread_local! { static BEFORE_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default(); }
