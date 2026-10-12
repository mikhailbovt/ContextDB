//! Exact native acceptance joins, independent of live derived rows.

use super::super::segments::types::AcceptedPublicationRef;
use super::*;
use serde::de::DeserializeOwned;

pub(super) const LOCATOR_OPERATION: &str = "raw_span_ann_prefix_locator_v2";

/// Only this module can mint the target consumed by complete prefix replay.
pub(super) struct VerifiedDensePrefixTarget {
    reference: AcceptedPublicationRef,
    receipt: DenseProjectionReceipt,
    manifest: DenseManifest,
    work: Vec<crate::capture::CaptureWork>,
}

impl VerifiedDensePrefixTarget {
    pub(super) fn reference(&self) -> &AcceptedPublicationRef {
        &self.reference
    }
    pub(super) fn receipt(&self) -> &DenseProjectionReceipt {
        &self.receipt
    }
    pub(super) fn manifest(&self) -> &DenseManifest {
        &self.manifest
    }
    pub(super) fn work(&self) -> &[crate::capture::CaptureWork] {
        &self.work
    }
}

pub(super) fn request_digest(
    database: &str,
    workspace: &str,
    request: &DensePrefixBaseRequestV2,
) -> ServiceResult<String> {
    canonical_digest(&(types::OPERATION, database, workspace, request))
}

pub(super) fn decode_allowance(
    bytes: &[u8],
    cap: usize,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    if bytes.len() > cap {
        return Err(integrity("prefix-base response exceeds its format bound"));
    }
    budget
        .charge(bytes.len() as u64 + 1, bytes.len() as u64 * 16 + 4096)
        .map_err(budget_error)
}

impl NativeService {
    pub(super) fn prefix_read<T: DeserializeOwned + Serialize, S: ReadSnapshot>(
        &self,
        snapshot: &S,
        keyspace: &contextdb_storage::Keyspace,
        key: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<T>> {
        self.prefix_read_at(snapshot, keyspace, key, types::ROW_BYTES, budget)
    }

    fn prefix_read_at<T: DeserializeOwned + Serialize, S: ReadSnapshot>(
        &self,
        snapshot: &S,
        keyspace: &contextdb_storage::Keyspace,
        key: &[u8],
        cap: usize,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<T>> {
        let Some(bytes) = crate::budgeted::read_value(snapshot, keyspace, key, cap, budget)? else {
            return Ok(None);
        };
        decode_allowance(&bytes, cap, budget)?;
        let value: T = decode(&bytes, "canonical prefix-base metadata")?;
        if encode(&value)? != bytes {
            return Err(integrity("prefix-base metadata is not canonical"));
        }
        Ok(Some(value))
    }

    fn prefix_accepted_response<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        reference: &AcceptedPublicationRef,
        operation: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(crate::StoredEvent, crate::StoredIdempotency)> {
        reference.validate()?;
        let event: crate::StoredEvent = self
            .prefix_read_at(
                snapshot,
                &self.keyspaces.events,
                &reference.global_commit.to_be_bytes(),
                crate::MAX_JSON_BYTES,
                budget,
            )?
            .ok_or_else(|| integrity("prefix-base accepted event absent"))?;
        let stored: crate::StoredIdempotency = self
            .prefix_read(
                snapshot,
                &self.keyspaces.idempotency,
                reference.request_digest.as_bytes(),
                budget,
            )?
            .ok_or_else(|| integrity("prefix-base accepted response absent"))?;
        if event.schema_version != crate::SCHEMA_VERSION
            || event.operation != operation
            || event.workspace_digest != workspace
            || event.global_commit != reference.global_commit
            || event.event_digest != reference.event_digest
            || event.event_digest != crate::event_digest(&event)?
            || event.request_digest != reference.request_digest
            || event.response_digest != reference.response_digest
            || stored.schema_version != crate::SCHEMA_VERSION
            || stored.operation != operation
            || stored.request_digest != reference.request_digest
            || stored.response_digest != reference.response_digest
            || stored.response_digest != digest_bytes(&stored.response_bytes)
        {
            return Err(integrity(
                "prefix-base native acceptance point join differs",
            ));
        }
        Ok((event, stored))
    }

    pub(super) fn prefix_publication_ref<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        global_commit: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AcceptedPublicationRef> {
        let event: crate::StoredEvent = self
            .prefix_read_at(
                snapshot,
                &self.keyspaces.events,
                &global_commit.to_be_bytes(),
                crate::MAX_JSON_BYTES,
                budget,
            )?
            .ok_or_else(|| integrity("prefix-base referenced event absent"))?;
        if event.schema_version != crate::SCHEMA_VERSION
            || event.global_commit != global_commit
            || event.event_digest != crate::event_digest(&event)?
        {
            return Err(integrity("prefix-base referenced event identity differs"));
        }
        Ok(AcceptedPublicationRef {
            global_commit,
            event_digest: event.event_digest,
            request_digest: event.request_digest,
            response_digest: event.response_digest,
        })
    }

    pub(super) fn verify_accepted_prefix_dense_target<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        reference: &AcceptedPublicationRef,
        budget: &mut QueryBudget,
    ) -> ServiceResult<VerifiedDensePrefixTarget> {
        let (receipt, manifest) =
            self.prefix_dense_target_binding(snapshot, workspace, reference, budget)?;
        let work = self.prefix_accepted_capture_work(
            snapshot,
            workspace,
            reference,
            manifest.through,
            budget,
        )?;
        Ok(VerifiedDensePrefixTarget {
            reference: reference.clone(),
            receipt,
            manifest,
            work,
        })
    }

    fn prefix_dense_target_binding<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        reference: &AcceptedPublicationRef,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(DenseProjectionReceipt, DenseManifest)> {
        let (event, stored) = self.prefix_accepted_response(
            snapshot,
            workspace,
            reference,
            dense::OPERATION,
            budget,
        )?;
        decode_allowance(&stored.response_bytes, types::MAX_PUBLICATION_BYTES, budget)?;
        let receipt: DenseProjectionReceipt =
            decode(&stored.response_bytes, "prefix dense target")?;
        self.check_dense_publication(&event, &receipt)?;
        if receipt.database_id != self.database_id
            || digest_bytes(receipt.workspace_id.as_bytes()) != workspace
            || encode(&receipt)? != stored.response_bytes
        {
            return Err(integrity(
                "prefix dense target owner or canonical response differs",
            ));
        }
        let manifest = receipt.manifest()?;
        Ok((receipt, manifest))
    }

    /// Maintenance-only native journal proof. Dense document commitments alone
    /// cannot detect a missing outbox item for a prepared-removed original.
    /// Every capture through the signed target is retained, including removals.
    fn prefix_accepted_capture_work<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        target: &AcceptedPublicationRef,
        through: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<crate::capture::CaptureWork>> {
        budget
            .charge(
                1,
                u64::from(types::MAX_WORK) * size_of::<crate::capture::CaptureWork>() as u64 * 2
                    + 4096,
            )
            .map_err(budget_error)?;
        let mut work = Vec::with_capacity(types::MAX_WORK as usize);
        let mut after: Option<Vec<u8>> = None;
        let mut previous_commit = 0_u64;
        let mut previous_digest: Option<String> = None;
        let mut previous_work = 0;
        'journal: loop {
            let page = crate::budgeted::metadata(snapshot, budget, |reader| {
                reader
                    .scan_prefix_page(
                        &self.keyspaces.events,
                        ScanPageRequest {
                            prefix: b"",
                            start_after: after.as_deref(),
                            max_entries: 32,
                            max_bytes: crate::MAX_JSON_BYTES + types::KEY_BYTES as usize + 256,
                        },
                    )
                    .map_err(storage_error)
            })?;
            for row in page.entries {
                decode_allowance(&row.value, crate::MAX_JSON_BYTES, budget)?;
                let event: crate::StoredEvent =
                    decode(&row.value, "prefix accepted capture census")?;
                if event.schema_version != crate::SCHEMA_VERSION
                    || row.key != event.global_commit.to_be_bytes()
                    || previous_commit.checked_add(1) != Some(event.global_commit)
                    || event.global_commit > target.global_commit
                    || event.previous_event_digest != previous_digest
                    || event.event_digest != crate::event_digest(&event)?
                    || (event.operation == "capture") != event.accepted_original.is_some()
                {
                    return Err(integrity(
                        "prefix native capture census has a missing or changed event",
                    ));
                }
                previous_commit = event.global_commit;
                previous_digest = Some(event.event_digest);
                if event.workspace_digest == workspace
                    && event.workspace_commit <= through
                    && let Some(accepted) = event.accepted_original
                {
                    if accepted.workspace_commit != event.workspace_commit
                        || accepted.workspace_commit <= previous_work
                    {
                        return Err(integrity("prefix accepted capture work order differs"));
                    }
                    if work.len() == types::MAX_WORK as usize {
                        return Err(exhausted(
                            "prefix complete accepted capture work exceeds 128",
                        ));
                    }
                    previous_work = accepted.workspace_commit;
                    work.push(accepted);
                }
                if previous_commit == target.global_commit {
                    break 'journal;
                }
            }
            let Some(next) = page.continuation else {
                return Err(integrity(
                    "prefix native capture census ends before accepted target",
                ));
            };
            if after.as_ref().is_some_and(|old| &next <= old) {
                return Err(integrity("prefix native capture census made no progress"));
            }
            after = Some(next);
        }
        if previous_digest.as_ref() != Some(&target.event_digest) {
            return Err(integrity(
                "prefix native capture census ends at a different target event",
            ));
        }
        Ok(work)
    }

    pub(super) fn verify_current_prefix_dense_target<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        requested: &DenseProjectionReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<VerifiedDensePrefixTarget> {
        let reference = self.recheck_current_prefix_dense_target(
            snapshot, workspace, generation, requested, budget,
        )?;
        self.verify_accepted_prefix_dense_target(snapshot, workspace, &reference, budget)
    }

    pub(super) fn recheck_current_prefix_dense_target<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        requested: &DenseProjectionReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AcceptedPublicationRef> {
        self.validate_dense_generation(snapshot, workspace, generation, budget)?;
        let live: DenseProjectionReceipt = self
            .prefix_read(
                snapshot,
                &self.keyspaces.continuous,
                &dense::receipt_key(workspace, generation.number),
                budget,
            )?
            .ok_or_else(stale_index)?;
        if &live != requested
            || live.generation != generation.number
            || live.raw_through != generation.through
            || live.raw_sources != generation.projected_sources
            || live.authorization_epoch != generation.authorization_epoch
        {
            return Err(stale_index());
        }
        let reference = self.prefix_publication_ref(snapshot, live.global_commit, budget)?;
        let (receipt, manifest) =
            self.prefix_dense_target_binding(snapshot, workspace, &reference, budget)?;
        if &receipt != requested || generation.dense.as_ref() != Some(&manifest) {
            return Err(integrity(
                "current prefix target differs from accepted dense state",
            ));
        }
        Ok(reference)
    }

    pub(super) fn require_prefix_base_feature<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let manifest: crate::Manifest = self
            .prefix_read(
                snapshot,
                &self.keyspaces.meta,
                crate::META_MANIFEST_KEY,
                budget,
            )?
            .ok_or_else(|| integrity("prefix-base format manifest absent"))?;
        crate::validate_manifest(&manifest, &self.database_id)?;
        if !manifest.features.contains(types::FEATURE)
            || !manifest.features.contains(dense::FEATURE)
            || !manifest.features.contains(bm25::FEATURE)
        {
            return Err(integrity("prefix-base required format feature absent"));
        }
        Ok(())
    }

    pub(super) fn check_prefix_base_acceptance<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        reference: &AcceptedPublicationRef,
        receipt: &DensePrefixBaseReceiptV2,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.check_prefix_base_receipt(receipt, budget)?;
        let (event, stored) = self.prefix_accepted_response(
            snapshot,
            workspace,
            reference,
            types::OPERATION,
            budget,
        )?;
        let manifest = &receipt.manifest;
        let (dense, target_manifest) =
            self.prefix_dense_target_binding(snapshot, workspace, &manifest.target, budget)?;
        if receipt.global_commit != reference.global_commit
            || receipt.database_id != self.database_id
            || digest_bytes(receipt.workspace_id.as_bytes()) != workspace
            || event.workspace_commit <= manifest.admitted_known_at
            || manifest.admitted_global_commit >= receipt.global_commit
            || manifest.target.global_commit > manifest.admitted_global_commit
            || manifest.prefix != target_manifest
            || dense.generation != manifest.raw.generation
            || dense.raw_through != manifest.raw.through
            || dense.raw_sources != manifest.raw.projected_sources
            || dense.authorization_epoch != manifest.raw.authorization_epoch
            || encode(receipt)? != stored.response_bytes
        {
            return Err(integrity("prefix-base frozen raw/dense acceptance differs"));
        }
        budget
            .charge(1, types::ROW_BYTES as u64)
            .map_err(budget_error)?;
        let request = DensePrefixBaseRequestV2 {
            generation: manifest.raw.generation,
            target: dense,
        };
        if request_digest(&self.database_id, workspace, &request)? != reference.request_digest {
            return Err(integrity("prefix-base accepted request identity differs"));
        }
        self.require_prefix_base_feature(snapshot, budget)
    }

    pub(crate) fn prefix_base_reference<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        receipt: &DensePrefixBaseReceiptV2,
        budget: &mut QueryBudget,
    ) -> ServiceResult<PrefixBaseRefV2> {
        let reference = self.prefix_publication_ref(snapshot, receipt.global_commit, budget)?;
        let workspace = digest_bytes(receipt.workspace_id.as_bytes());
        self.check_prefix_base_acceptance(snapshot, &workspace, &reference, receipt, budget)?;
        let result = PrefixBaseRefV2 {
            global_commit: reference.global_commit,
            request_digest: reference.request_digest,
            response_digest: reference.response_digest,
            receipt_digest: digest(&encode(receipt)?),
            content_digest: receipt.manifest.content_digest,
        };
        result.validate()?;
        Ok(result)
    }

    pub(crate) fn accepted_prefix_base<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DensePrefixBaseReceiptV2> {
        budget.charge(1, types::KEY_BYTES).map_err(budget_error)?;
        let key = retained_locator_key(workspace, generation)?;
        let stored: crate::StoredIdempotency = self
            .prefix_read(snapshot, &self.keyspaces.idempotency, &key, budget)?
            .ok_or_else(|| integrity("retained prefix-base locator absent"))?;
        decode_allowance(&stored.response_bytes, types::MAX_PUBLICATION_BYTES, budget)?;
        let locator: RetainedPrefixBaseLocatorV2 =
            decode(&stored.response_bytes, "prefix-base locator")?;
        self.check_retained_prefix_base_locator(workspace, &locator, budget)?;
        if locator.workspace_digest != workspace
            || locator.generation != generation
            || stored.schema_version != crate::SCHEMA_VERSION
            || stored.operation != LOCATOR_OPERATION
            || stored.request_digest != canonical_digest(&locator)?
            || stored.response_digest != digest_bytes(&stored.response_bytes)
            || stored.response_bytes != encode(&locator)?
        {
            return Err(integrity("prefix-base retained locator envelope differs"));
        }
        let (_, accepted) = self.prefix_accepted_response(
            snapshot,
            workspace,
            &locator.publication,
            types::OPERATION,
            budget,
        )?;
        decode_allowance(
            &accepted.response_bytes,
            types::MAX_PUBLICATION_BYTES,
            budget,
        )?;
        let receipt: DensePrefixBaseReceiptV2 =
            decode(&accepted.response_bytes, "accepted prefix base")?;
        self.check_prefix_base_acceptance(
            snapshot,
            workspace,
            &locator.publication,
            &receipt,
            budget,
        )?;
        if receipt.manifest.raw.generation != generation {
            return Err(integrity("prefix-base retained generation differs"));
        }
        Ok(receipt)
    }

    /// Offline declarations use one supplied parent and remain after full GC.
    pub(in crate::raw_index) fn prefix_base_declarations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<(String, u64), DensePrefixBaseReceiptV2>> {
        let mut declarations = BTreeMap::new();
        let mut after: Option<Vec<u8>> = None;
        let mut previous = 0;
        loop {
            let page = crate::budgeted::metadata(snapshot, budget, |reader| {
                reader
                    .scan_prefix_page(
                        &self.keyspaces.events,
                        ScanPageRequest {
                            prefix: b"",
                            start_after: after.as_deref(),
                            max_entries: 32,
                            max_bytes: crate::MAX_JSON_BYTES + types::KEY_BYTES as usize + 256,
                        },
                    )
                    .map_err(storage_error)
            })?;
            for row in page.entries {
                decode_allowance(&row.value, crate::MAX_JSON_BYTES, budget)?;
                let event: crate::StoredEvent =
                    decode(&row.value, "prefix-base declaration event")?;
                if row.key != event.global_commit.to_be_bytes() || event.global_commit <= previous {
                    return Err(integrity("prefix-base declaration order differs"));
                }
                previous = event.global_commit;
                if event.operation != types::OPERATION {
                    continue;
                }
                let reference =
                    self.prefix_publication_ref(snapshot, event.global_commit, budget)?;
                let (_, stored) = self.prefix_accepted_response(
                    snapshot,
                    &event.workspace_digest,
                    &reference,
                    types::OPERATION,
                    budget,
                )?;
                decode_allowance(&stored.response_bytes, types::MAX_PUBLICATION_BYTES, budget)?;
                let receipt: DensePrefixBaseReceiptV2 =
                    decode(&stored.response_bytes, "prefix-base declaration")?;
                self.check_prefix_base_acceptance(
                    snapshot,
                    &event.workspace_digest,
                    &reference,
                    &receipt,
                    budget,
                )?;
                let retained = self.accepted_prefix_base(
                    snapshot,
                    &event.workspace_digest,
                    receipt.manifest.raw.generation,
                    budget,
                )?;
                if retained != receipt {
                    return Err(integrity(
                        "prefix-base declaration differs from retained locator",
                    ));
                }
                budget
                    .charge(1, types::ROW_BYTES as u64)
                    .map_err(budget_error)?;
                let key = (event.workspace_digest, receipt.manifest.raw.generation);
                if declarations.insert(key, receipt).is_some() {
                    return Err(integrity(
                        "raw generation has multiple accepted prefix bases",
                    ));
                }
            }
            let Some(next) = page.continuation else {
                break;
            };
            if after.as_ref().is_some_and(|old| &next <= old) {
                return Err(integrity("prefix-base declaration scan made no progress"));
            }
            after = Some(next);
        }
        if !declarations.is_empty() {
            self.require_prefix_base_feature(snapshot, budget)?;
        }
        Ok(declarations)
    }
}
