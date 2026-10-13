//! Native dense acceptance and complete capture intervals are separate proofs.

use super::super::prefix_v2::verification::VerifiedDensePrefixTarget;
use super::super::segments::crypto::metered_json_len;
use super::types::{AcceptedPublicationRef, CaptureBoundaryRefV2, KEY_BYTES, MAX_WORK, ROW_BYTES};
use crate::capture::CaptureWork;
use crate::raw_index::{
    budget_error,
    dense::{DenseManifest, DenseProjectionReceipt},
};
use crate::{NativeService, decode, encode, integrity, storage_error};
use contextdb_recall::QueryBudget;
use contextdb_service::ServiceResult;
use contextdb_storage::{ReadSnapshot, ScanPageRequest};
use std::mem::size_of;

pub(in crate::raw_index::dense::graph) struct VerifiedDenseState {
    reference: AcceptedPublicationRef,
    receipt: DenseProjectionReceipt,
    manifest: DenseManifest,
}
impl VerifiedDenseState {
    pub(in crate::raw_index::dense::graph) fn reference(&self) -> &AcceptedPublicationRef {
        &self.reference
    }
    pub(in crate::raw_index::dense::graph) fn receipt(&self) -> &DenseProjectionReceipt {
        &self.receipt
    }
    pub(in crate::raw_index::dense::graph) fn manifest(&self) -> &DenseManifest {
        &self.manifest
    }
}

pub(in crate::raw_index::dense::graph) struct VerifiedCaptureBoundary {
    reference: CaptureBoundaryRefV2,
}
impl VerifiedCaptureBoundary {
    pub(in crate::raw_index::dense::graph) fn reference(&self) -> &CaptureBoundaryRefV2 {
        &self.reference
    }
}

pub(in crate::raw_index::dense::graph) struct VerifiedPrefixSegmentInterval {
    before: VerifiedDenseState,
    after: VerifiedDenseState,
    start: VerifiedCaptureBoundary,
    end: VerifiedCaptureBoundary,
    work: Vec<CaptureWork>,
}
impl VerifiedPrefixSegmentInterval {
    pub(in crate::raw_index::dense::graph) fn before(&self) -> &VerifiedDenseState {
        &self.before
    }
    pub(in crate::raw_index::dense::graph) fn after(&self) -> &VerifiedDenseState {
        &self.after
    }
    pub(in crate::raw_index::dense::graph) fn start(&self) -> &VerifiedCaptureBoundary {
        &self.start
    }
    pub(in crate::raw_index::dense::graph) fn end(&self) -> &VerifiedCaptureBoundary {
        &self.end
    }
    pub(in crate::raw_index::dense::graph) fn work(&self) -> &[CaptureWork] {
        &self.work
    }
}

impl NativeService {
    /// Point acceptance alone has no total-source census cap and no current
    /// content authority. Complete <=128 interval work is proved separately.
    pub(in crate::raw_index::dense::graph) fn verify_prefix_segment_dense_state<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        reference: &AcceptedPublicationRef,
        parent: &mut QueryBudget,
    ) -> ServiceResult<VerifiedDenseState> {
        let bytes = metered_json_len(reference, parent, ROW_BYTES)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 8 + 1024)
            .map_err(budget_error)?;
        let (receipt, manifest) =
            self.prefix_dense_target_binding(snapshot, workspace, reference, parent)?;
        Ok(VerifiedDenseState {
            reference: reference.clone(),
            receipt,
            manifest,
        })
    }

    fn mint_prefix_capture_boundary<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        work: &CaptureWork,
        parent: &mut QueryBudget,
    ) -> ServiceResult<VerifiedCaptureBoundary> {
        parent
            .charge(1, size_of::<CaptureBoundaryRefV2>() as u64 + 1024)
            .map_err(budget_error)?;
        let (global_commit, event_digest, receipt_digest, control_digest) =
            self.verified_capture_boundary_metadata(snapshot, workspace, work, parent)?;
        let reference = CaptureBoundaryRefV2 {
            work: work.clone(),
            global_commit,
            event_digest,
            receipt_digest,
            control_digest,
        };
        reference.validate()?;
        Ok(VerifiedCaptureBoundary { reference })
    }

    pub(in crate::raw_index::dense::graph) fn first_prefix_segment_capture_boundary<
        S: ReadSnapshot,
    >(
        &self,
        snapshot: &S,
        workspace: &str,
        target: &VerifiedDensePrefixTarget,
        parent: &mut QueryBudget,
    ) -> ServiceResult<VerifiedCaptureBoundary> {
        let work = target
            .work()
            .last()
            .ok_or_else(|| integrity("nonempty prefix base has no capture boundary"))?;
        if target.work().len() > MAX_WORK as usize
            || work.workspace_commit > target.manifest().through
        {
            return Err(integrity(
                "prefix base capture boundary escapes its complete census",
            ));
        }
        let result = self.mint_prefix_capture_boundary(snapshot, workspace, work, parent)?;
        if result.reference.global_commit >= target.reference().global_commit {
            return Err(integrity(
                "prefix capture boundary follows its dense acceptance",
            ));
        }
        Ok(result)
    }

    pub(in crate::raw_index::dense::graph) fn verify_prefix_segment_capture_boundary<
        S: ReadSnapshot,
    >(
        &self,
        snapshot: &S,
        workspace: &str,
        reference: &CaptureBoundaryRefV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<VerifiedCaptureBoundary> {
        reference.validate()?;
        let actual =
            self.mint_prefix_capture_boundary(snapshot, workspace, &reference.work, parent)?;
        if &actual.reference != reference {
            return Err(integrity(
                "retained prefix capture boundary differs from actual acceptance",
            ));
        }
        Ok(actual)
    }

    /// Scan AFTER the capture, not either dense/base publication. A pre-recorded
    /// backlog can precede both publications. Future captures remain part of the
    /// authenticated chain but cannot become work for this accepted cutoff.
    #[allow(
        clippy::too_many_arguments,
        reason = "opaque state and actual capture range stay explicit"
    )]
    pub(in crate::raw_index::dense::graph) fn verify_prefix_segment_interval<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        before: VerifiedDenseState,
        after: VerifiedDenseState,
        start: VerifiedCaptureBoundary,
        parent: &mut QueryBudget,
    ) -> ServiceResult<VerifiedPrefixSegmentInterval> {
        parent.check().map_err(budget_error)?;
        let old = before.manifest();
        let new = after.manifest();
        if before.receipt.generation != after.receipt.generation
            || before.receipt.authorization_epoch != after.receipt.authorization_epoch
            || before.receipt.database_id != self.database_id
            || after.receipt.database_id != self.database_id
            || before.receipt.workspace_id != after.receipt.workspace_id
            || before.receipt.raw_through > after.receipt.raw_through
            || before.receipt.raw_sources > after.receipt.raw_sources
            || old.profile != new.profile
            || old.profile_digest != new.profile_digest
            || old.vector_space_id != new.vector_space_id
            || old.through >= new.through
            || before.reference.global_commit >= after.reference.global_commit
            || start.reference.work.workspace_commit > old.through
            || start.reference.global_commit >= before.reference.global_commit
            || old.sources > new.sources
            || old.spans > new.spans
            || old.embedded_sources > new.embedded_sources
            || old.omitted_sources > new.omitted_sources
        {
            return Err(integrity(
                "prefix interval state or authenticated capture start differs",
            ));
        }
        parent
            .charge(
                1,
                u64::from(MAX_WORK) * size_of::<CaptureWork>() as u64 * 2 + 4096,
            )
            .map_err(budget_error)?;
        let mut work = Vec::with_capacity(MAX_WORK as usize);
        let mut previous_commit = start.reference.global_commit;
        let mut previous_digest = start.reference.event_digest.clone();
        let mut previous_workspace = start.reference.work.workspace_commit;
        let mut after_key = previous_commit.to_be_bytes().to_vec();
        'journal: loop {
            let page = crate::budgeted::metadata(snapshot, parent, |reader| {
                reader
                    .scan_prefix_page(
                        &self.keyspaces.events,
                        ScanPageRequest {
                            prefix: b"",
                            start_after: Some(&after_key),
                            max_entries: 32,
                            max_bytes: crate::MAX_JSON_BYTES + KEY_BYTES as usize + 256,
                        },
                    )
                    .map_err(storage_error)
            })?;
            for row in page.entries {
                if row.value.len() > crate::MAX_JSON_BYTES {
                    return Err(integrity(
                        "prefix interval journal row exceeds native bound",
                    ));
                }
                parent
                    .charge(
                        row.value.len() as u64 * 8 + 1,
                        row.value.len() as u64 * 16 + 8192,
                    )
                    .map_err(budget_error)?;
                let event: crate::StoredEvent =
                    decode(&row.value, "complete prefix capture interval")?;
                if event.schema_version != crate::SCHEMA_VERSION
                    || row.key != event.global_commit.to_be_bytes()
                    || previous_commit.checked_add(1) != Some(event.global_commit)
                    || event.global_commit > after.reference.global_commit
                    || event.previous_event_digest.as_ref() != Some(&previous_digest)
                    || event.event_digest != crate::event_digest(&event)?
                    || encode(&event)? != row.value
                    || (event.operation == "capture") != event.accepted_original.is_some()
                {
                    return Err(integrity(
                        "prefix interval native chain has a missing or changed event",
                    ));
                }
                previous_commit = event.global_commit;
                previous_digest = event.event_digest;
                if event.workspace_digest == workspace {
                    if event.workspace_commit <= previous_workspace {
                        return Err(integrity(
                            "prefix interval workspace history is not ordered",
                        ));
                    }
                    previous_workspace = event.workspace_commit;
                    if let Some(accepted) = event.accepted_original {
                        if accepted.workspace_commit != event.workspace_commit {
                            return Err(integrity("prefix interval capture position differs"));
                        }
                        if accepted.workspace_commit <= old.through {
                            return Err(integrity(
                                "prefix interval start is not the last before-cutoff capture",
                            ));
                        }
                        if accepted.workspace_commit <= new.through {
                            if work.len() == MAX_WORK as usize {
                                return Err(crate::exhausted(
                                    "prefix interval complete accepted work exceeds 128",
                                ));
                            }
                            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
                            let actual: CaptureWork = self
                                .graph_read(
                                    snapshot,
                                    &self.keyspaces.continuous,
                                    &crate::capture::work_key(workspace, accepted.workspace_commit),
                                    parent,
                                )?
                                .ok_or_else(|| {
                                    integrity("prefix interval accepted outbox work is absent")
                                })?;
                            if actual != accepted {
                                return Err(integrity(
                                    "prefix interval outbox work differs from accepted history",
                                ));
                            }
                            work.push(accepted);
                        }
                    }
                }
                if previous_commit == after.reference.global_commit {
                    break 'journal;
                }
            }
            let Some(next) = page.continuation else {
                return Err(integrity(
                    "prefix interval journal ends before accepted dense target",
                ));
            };
            if next <= after_key {
                return Err(integrity("prefix interval native range made no progress"));
            }
            after_key = next;
        }
        if previous_digest != after.reference.event_digest {
            return Err(integrity(
                "prefix interval ends at a different accepted dense event",
            ));
        }
        let last = work
            .last()
            .ok_or_else(|| crate::invalid("prefix interval contains no accepted capture work"))?;
        let end = self.mint_prefix_capture_boundary(snapshot, workspace, last, parent)?;
        if end.reference.global_commit <= start.reference.global_commit
            || end.reference.global_commit >= after.reference.global_commit
        {
            return Err(integrity(
                "prefix interval ending capture escapes its authenticated range",
            ));
        }
        Ok(VerifiedPrefixSegmentInterval {
            before,
            after,
            start,
            end,
            work,
        })
    }
}
