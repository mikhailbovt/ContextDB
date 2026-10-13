//! Projection recency from a genuine dense acceptance to the certified head.

use super::*;
use crate::raw_index::RawProjectionProgress;
use contextdb_storage::ScanPageRequest;

impl NativeService {
    /// A live accepted receipt alone cannot exclude a coherent older row replay.
    /// Close its native suffix under the same parent; never restart at genesis.
    #[expect(
        clippy::too_many_arguments,
        reason = "The snapshot, accepted target and certified endpoint are explicit proof inputs"
    )]
    pub(in crate::raw_index::dense::graph::routing) fn check_routed_projection_recency<
        S: ReadSnapshot,
    >(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        current: &DenseProjectionReceipt,
        current_ref: &AcceptedPublicationRef,
        world: &crate::WorkspaceState,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent.charge(1, 8192).map_err(budget_error)?;
        if current.generation != generation.number
            || current.global_commit != current_ref.global_commit
            || current_ref.global_commit > world.latest_global_commit
            || world.workspace_digest != workspace
        {
            return Err(integrity("routed projection recency anchor differs"));
        }
        let (anchor, _) = self.prefix_accepted_response(
            snapshot,
            workspace,
            current_ref,
            dense::OPERATION,
            parent,
        )?;
        self.check_dense_publication(&anchor, current)?;
        let mut previous_commit = anchor.global_commit;
        let mut previous_digest = anchor.event_digest;
        let mut previous_workspace = anchor.workspace_commit;
        let mut raw_through = current.raw_through;
        let mut raw_sources = current.raw_sources;
        let mut after = previous_commit.to_be_bytes().to_vec();
        while previous_commit < world.latest_global_commit {
            parent.check().map_err(budget_error)?;
            let page = crate::budgeted::metadata(snapshot, parent, |reader| {
                reader
                    .scan_prefix_page(
                        &self.keyspaces.events,
                        ScanPageRequest {
                            prefix: b"",
                            start_after: Some(&after),
                            max_entries: 32,
                            max_bytes: crate::MAX_JSON_BYTES + KEY_BYTES as usize + 256,
                        },
                    )
                    .map_err(storage_error)
            })?;
            for row in page.entries {
                if row.value.len() > crate::MAX_JSON_BYTES {
                    return Err(integrity("routed projection successor exceeds row bound"));
                }
                parent
                    .charge(
                        row.value.len() as u64 * 8 + 1,
                        row.value.len() as u64 * 16 + 8192,
                    )
                    .map_err(budget_error)?;
                let event: crate::StoredEvent = decode(&row.value, "routed projection successor")?;
                if event.schema_version != crate::SCHEMA_VERSION
                    || row.key != event.global_commit.to_be_bytes()
                    || previous_commit.checked_add(1) != Some(event.global_commit)
                    || event.global_commit > world.latest_global_commit
                    || event.previous_event_digest.as_ref() != Some(&previous_digest)
                    || event.event_digest != crate::event_digest(&event)?
                    || encode(&event)? != row.value
                    || (event.operation == "capture") != event.accepted_original.is_some()
                {
                    return Err(integrity(
                        "routed projection successor chain has a changed or missing frame",
                    ));
                }
                if event.workspace_digest == workspace {
                    if previous_workspace.checked_add(1) != Some(event.workspace_commit) {
                        return Err(integrity("routed projection workspace successor gap"));
                    }
                    previous_workspace = event.workspace_commit;
                    if event.operation == dense::OPERATION {
                        return Err(stale_index());
                    }
                    if event.operation == bm25::OPERATION || event.operation == "raw_projection" {
                        let reference =
                            self.prefix_publication_ref(snapshot, event.global_commit, parent)?;
                        let (_, stored) = self.prefix_accepted_response(
                            snapshot,
                            workspace,
                            &reference,
                            &event.operation,
                            parent,
                        )?;
                        prefix_v2::verification::decode_allowance(
                            &stored.response_bytes,
                            ROW_BYTES,
                            parent,
                        )?;
                        let progress: RawProjectionProgress =
                            decode(&stored.response_bytes, "routed accepted raw successor")?;
                        if encode(&progress)? != stored.response_bytes
                            || progress.generation == 0
                            || progress.through >= event.workspace_commit
                            || progress.projected_sources > progress.through
                        {
                            return Err(integrity("routed accepted raw successor differs"));
                        }
                        if progress.generation == generation.number {
                            if event.operation != bm25::OPERATION
                                || progress.through < raw_through
                                || progress.projected_sources < raw_sources
                                || (progress.through == raw_through
                                    && progress.projected_sources != raw_sources)
                            {
                                return Err(integrity("routed raw successor moved backwards"));
                            }
                            raw_through = progress.through;
                            raw_sources = progress.projected_sources;
                        } else if progress.caught_up {
                            // A completed replacement changes the active index.
                            return Err(stale_index());
                        }
                    }
                }
                previous_commit = event.global_commit;
                previous_digest = event.event_digest;
                if previous_commit == world.latest_global_commit {
                    break;
                }
            }
            if previous_commit == world.latest_global_commit {
                break;
            }
            let next = page.continuation.ok_or_else(|| {
                integrity("routed projection successor chain ends before current head")
            })?;
            if next <= after {
                return Err(integrity(
                    "routed projection successor chain made no progress",
                ));
            }
            after = next;
        }
        let head: crate::StoredEvent = self
            .prefix_read_at(
                snapshot,
                &self.keyspaces.events,
                &world.latest_global_commit.to_be_bytes(),
                crate::MAX_JSON_BYTES,
                parent,
            )?
            .ok_or_else(|| integrity("routed current successor endpoint absent"))?;
        if previous_commit != world.latest_global_commit
            || previous_digest != head.event_digest
            || head.event_digest != crate::event_digest(&head)?
            || head.workspace_digest != workspace
            || head.workspace_commit != world.watermarks.journal
            || previous_workspace != world.watermarks.journal
            || raw_through != generation.through
            || raw_sources != generation.projected_sources
        {
            return Err(integrity("routed current projection endpoint differs"));
        }
        parent.check().map_err(budget_error)
    }
}
