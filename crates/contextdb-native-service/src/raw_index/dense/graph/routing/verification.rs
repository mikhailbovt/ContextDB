//! Independent native acceptance, retained revisions and current owner admission.

use super::super::prefix_v2::verification::decode_allowance;
use super::*;

pub(super) fn directory_router_request_digest(
    database: &str,
    workspace: &str,
    request: &DirectoryRouterPublishRequestV1,
    parent: &mut QueryBudget,
) -> ServiceResult<String> {
    let bytes = segments::crypto::metered_encode(
        &(OPERATION, database, workspace, request),
        parent,
        ROW_BYTES,
    )?;
    parent
        .charge(bytes.len() as u64 + 1, 0)
        .map_err(budget_error)?;
    Ok(digest_bytes(&bytes))
}

impl NativeService {
    pub(super) fn require_directory_router_feature<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let manifest: crate::Manifest = self
            .prefix_read(
                snapshot,
                &self.keyspaces.meta,
                crate::META_MANIFEST_KEY,
                parent,
            )?
            .ok_or_else(|| integrity("directory router format manifest absent"))?;
        crate::validate_manifest(&manifest, &self.database_id)?;
        if !manifest.features.contains(FEATURE)
            || !manifest.features.contains(prefix_v2::types::FEATURE)
            || !manifest.features.contains(dense::FEATURE)
        {
            return Err(integrity("directory router required native format absent"));
        }
        Ok(())
    }

    /// A bounded exact primary/event point join, without recursive predecessor replay.
    pub(in crate::raw_index::dense::graph) fn directory_router_point_receipt<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        reference: &AcceptedPublicationRef,
        parent: &mut QueryBudget,
    ) -> ServiceResult<DirectoryRouterReceiptV1> {
        let (_, stored) =
            self.prefix_accepted_response(snapshot, workspace, reference, OPERATION, parent)?;
        decode_allowance(&stored.response_bytes, MAX_PUBLICATION_BYTES, parent)?;
        let receipt: DirectoryRouterReceiptV1 =
            decode(&stored.response_bytes, "native accepted directory router")?;
        self.check_directory_router_receipt(&receipt, parent)?;
        if receipt.database_id != self.database_id
            || digest_bytes(receipt.workspace_id.as_bytes()) != workspace
            || receipt.global_commit != reference.global_commit
            || segments::crypto::metered_encode(&receipt, parent, MAX_PUBLICATION_BYTES)?
                != stored.response_bytes
        {
            return Err(integrity(
                "directory router native point acceptance differs",
            ));
        }
        Ok(receipt)
    }

    pub(super) fn check_directory_router_acceptance<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        reference: &AcceptedPublicationRef,
        receipt: &DirectoryRouterReceiptV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let accepted =
            self.directory_router_point_receipt(snapshot, workspace, reference, parent)?;
        let manifest = &receipt.manifest;
        let (event, _) =
            self.prefix_accepted_response(snapshot, workspace, reference, OPERATION, parent)?;
        if &accepted != receipt
            || manifest.admitted_global_commit.checked_add(1) != Some(receipt.global_commit)
            || manifest.admitted_known_at.checked_add(1) != Some(event.workspace_commit)
        {
            return Err(integrity(
                "directory router differs from exact native acceptance",
            ));
        }
        let request = DirectoryRouterPublishRequestV1 {
            generation: manifest.raw.generation,
            previous: manifest.previous.clone(),
            coverage: manifest.coverage.clone(),
        };
        if directory_router_request_digest(&self.database_id, workspace, &request, parent)?
            != reference.request_digest
        {
            return Err(integrity(
                "directory router accepted request identity differs",
            ));
        }
        let base =
            self.accepted_prefix_base(snapshot, workspace, manifest.raw.generation, parent)?;
        if self.prefix_segment_base_reference(snapshot, workspace, &base, parent)?
            != manifest.coverage.base
            || manifest.raw.custody_version != base.manifest.raw.custody_version
            || manifest.raw.analyzer != base.manifest.raw.analyzer
            || manifest.raw.bm25 != base.manifest.raw.bm25
            || manifest.raw.authorization_epoch != base.manifest.raw.authorization_epoch
            || manifest.raw.removal_through != base.manifest.raw.removal_through
            || manifest.raw.through < base.manifest.raw.through
            || manifest.raw.projected_sources < base.manifest.raw.projected_sources
        {
            return Err(integrity(
                "directory router lost its genuine prefix base/raw binding",
            ));
        }
        if let Some(directory) = &manifest.coverage.directory {
            let latest = self.accepted_prefix_segment_for_ordinal(
                snapshot,
                workspace,
                manifest.raw.generation,
                directory.count,
                parent,
            )?;
            if self.prefix_segment_directory_reference(snapshot, &latest.directory, parent)?
                != *directory
                || latest.directory.head.base != manifest.coverage.base
                || latest.directory.head.covered != manifest.covered
                || latest.directory.head.covered_dense != manifest.covered_dense
                || latest.directory.head.ending != manifest.ending
                || latest.delta.manifest.raw.through > manifest.raw.through
                || latest.delta.manifest.raw.projected_sources > manifest.raw.projected_sources
            {
                return Err(integrity(
                    "directory router covered head differs from retained fine acceptance",
                ));
            }
        } else {
            let prefix = self.verify_accepted_prefix_dense_target(
                snapshot,
                workspace,
                &base.manifest.target,
                parent,
            )?;
            let ending =
                self.first_prefix_segment_capture_boundary(snapshot, workspace, &prefix, parent)?;
            if manifest.covered != base.manifest.prefix
                || manifest.covered_dense != base.manifest.target
                || ending.reference() != &manifest.ending
            {
                return Err(integrity(
                    "base-only router covered state differs from native prefix",
                ));
            }
        }
        let dense = self.verify_prefix_segment_dense_state(
            snapshot,
            workspace,
            &manifest.covered_dense,
            parent,
        )?;
        self.verify_prefix_segment_capture_boundary(snapshot, workspace, &manifest.ending, parent)?;
        if dense.manifest() != &manifest.covered
            || manifest.ending.work.workspace_commit > manifest.covered.through
            || dense.receipt().raw_through > manifest.raw.through
            || dense.receipt().raw_sources > manifest.raw.projected_sources
        {
            return Err(integrity(
                "directory router lost genuine covered dense/capture authority",
            ));
        }
        let (space_digest, space_id) =
            self.directory_router_space_fields(&manifest.covered, &manifest.recipe, parent)?;
        if space_digest != manifest.coarse_space_digest || space_id != manifest.coarse_space_id {
            return Err(integrity(
                "directory router derived space differs from declared genuine profile",
            ));
        }
        if let Some(previous) = &manifest.previous {
            let previous_ref =
                self.prefix_publication_ref(snapshot, previous.global_commit, parent)?;
            let previous_receipt =
                self.directory_router_point_receipt(snapshot, workspace, &previous_ref, parent)?;
            let previous_bytes =
                segments::crypto::metered_encode(&previous_receipt, parent, MAX_PUBLICATION_BYTES)?;
            if previous_ref.request_digest != previous.request_digest
                || previous_ref.response_digest != previous.response_digest
                || digest(&previous_bytes) != previous.receipt_digest
                || previous_receipt.manifest.content_digest != previous.content_digest
                || previous_receipt.manifest.serial != previous.serial
                || previous.serial.checked_add(1) != Some(manifest.serial)
                || previous_receipt.manifest.raw.generation != manifest.raw.generation
                || previous_receipt.manifest.coverage.base != manifest.coverage.base
                || previous_receipt.manifest.coverage.count()? >= manifest.coverage.count()?
                || previous_receipt.manifest.covered.profile != manifest.covered.profile
                || previous_receipt.manifest.raw.through > manifest.raw.through
                || previous_receipt.manifest.raw.projected_sources > manifest.raw.projected_sources
            {
                return Err(integrity("directory router immutable predecessor differs"));
            }
        }
        self.require_directory_router_feature(snapshot, parent)
    }

    pub(crate) fn directory_router_reference<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        receipt: &DirectoryRouterReceiptV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<DirectoryRouterRefV1> {
        let workspace = digest_bytes(receipt.workspace_id.as_bytes());
        let accepted = self.prefix_publication_ref(snapshot, receipt.global_commit, parent)?;
        self.check_directory_router_acceptance(snapshot, &workspace, &accepted, receipt, parent)?;
        let bytes = segments::crypto::metered_encode(receipt, parent, MAX_PUBLICATION_BYTES)?;
        let result = DirectoryRouterRefV1 {
            serial: receipt.manifest.serial,
            global_commit: accepted.global_commit,
            request_digest: accepted.request_digest,
            response_digest: accepted.response_digest,
            receipt_digest: digest(&bytes),
            content_digest: receipt.manifest.content_digest,
        };
        result.validate()?;
        Ok(result)
    }

    pub(crate) fn accepted_directory_router<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        serial: u64,
        parent: &mut QueryBudget,
    ) -> ServiceResult<DirectoryRouterReceiptV1> {
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let key = retained_locator_key(workspace, generation, serial)?;
        let stored: crate::StoredIdempotency = self
            .prefix_read(snapshot, &self.keyspaces.idempotency, &key, parent)?
            .ok_or_else(|| integrity("retained directory router locator absent"))?;
        decode_allowance(&stored.response_bytes, MAX_PUBLICATION_BYTES, parent)?;
        let locator: RetainedDirectoryRouterLocatorV1 = decode(
            &stored.response_bytes,
            "retained native directory router locator",
        )?;
        self.check_retained_directory_router_locator(workspace, &locator, parent)?;
        if locator.workspace_digest != workspace
            || locator.generation != generation
            || locator.serial != serial
            || stored.schema_version != crate::SCHEMA_VERSION
            || stored.operation != LOCATOR_OPERATION
            || stored.request_digest != canonical_digest(&locator)?
            || stored.response_digest != digest_bytes(&stored.response_bytes)
            || segments::crypto::metered_encode(&locator, parent, MAX_PUBLICATION_BYTES)?
                != stored.response_bytes
        {
            return Err(integrity(
                "retained directory router locator binding differs",
            ));
        }
        let receipt =
            self.directory_router_point_receipt(snapshot, workspace, &locator.publication, parent)?;
        self.check_directory_router_acceptance(
            snapshot,
            workspace,
            &locator.publication,
            &receipt,
            parent,
        )?;
        if receipt.manifest.raw.generation != generation || receipt.manifest.serial != serial {
            return Err(integrity("retained directory router revision differs"));
        }
        Ok(receipt)
    }

    pub(super) fn accepted_current_directory_router<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_id: &str,
        generation: &Generation,
        parent: &mut QueryBudget,
    ) -> ServiceResult<DirectoryRouterReceiptV1> {
        let workspace = digest_bytes(workspace_id.as_bytes());
        let reference = generation
            .dense_directory_router
            .as_ref()
            .ok_or_else(stale_index)?;
        let world = self.current_directory_router_heads(snapshot, workspace_id, parent)?;
        if world
            .directory_routers
            .as_ref()
            .and_then(|roots| roots.get(&generation.number))
            != Some(reference)
        {
            return Err(integrity(
                "directory router generation differs from current certified root",
            ));
        }
        let receipt = self.accepted_directory_router(
            snapshot,
            &workspace,
            generation.number,
            reference.serial,
            parent,
        )?;
        if self.directory_router_reference(snapshot, &receipt, parent)? != *reference {
            return Err(integrity(
                "current directory router root differs from retained native acceptance",
            ));
        }
        let live: DirectoryRouterReceiptV1 = self
            .prefix_read(
                snapshot,
                &self.keyspaces.continuous,
                &head_key(&workspace, generation.number)?,
                parent,
            )?
            .ok_or_else(|| integrity("current directory router head absent"))?;
        self.check_directory_router_generation_binding(
            snapshot, &workspace, generation, &receipt, parent,
        )?;
        if live != receipt {
            return Err(integrity(
                "live directory router differs from accepted current revision",
            ));
        }
        Ok(receipt)
    }

    pub(in crate::raw_index) fn check_directory_router_generation_binding<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        receipt: &DirectoryRouterReceiptV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let manifest = &receipt.manifest;
        let raw = &manifest.raw;
        let dense = generation
            .dense
            .as_ref()
            .ok_or_else(|| integrity("router generation lost dense profile"))?;
        let base = self.accepted_prefix_base(snapshot, workspace, generation.number, parent)?;
        self.check_prefix_generation_binding(snapshot, workspace, generation, &base, parent)?;
        let latest = generation
            .dense_directory_router
            .as_ref()
            .ok_or_else(|| integrity("generation lost its native directory router"))?;
        if receipt.database_id != self.database_id
            || digest_bytes(receipt.workspace_id.as_bytes()) != workspace
            || raw.generation != generation.number
            || raw.custody_version != generation.custody_version
            || raw.analyzer != generation.analyzer
            || generation.bm25.as_ref() != Some(&raw.bm25)
            || raw.authorization_epoch != generation.authorization_epoch
            || raw.removal_through != generation.removal_through
            || raw.through > generation.through
            || raw.projected_sources > generation.projected_sources
            || (raw.through == generation.through
                && raw.projected_sources != generation.projected_sources)
            || manifest.covered.profile != dense.profile
            || manifest.covered.profile_digest != dense.profile_digest
            || manifest.covered.vector_space_id != dense.vector_space_id
            || manifest.covered.through > dense.through
            || manifest.covered.sources > dense.sources
            || manifest.covered.spans > dense.spans
            || manifest.covered.embedded_sources > dense.embedded_sources
            || manifest.covered.omitted_sources > dense.omitted_sources
            || (manifest.covered.through == dense.through && manifest.covered != *dense)
            || latest.serial < manifest.serial
            || latest.global_commit < receipt.global_commit
            || manifest.coverage.directory.as_ref().is_some_and(|covered| {
                generation
                    .dense_prefix_segments
                    .as_ref()
                    .is_none_or(|current| {
                        current.count < covered.count
                            || (current.count == covered.count && current != covered)
                    })
            })
        {
            return Err(integrity(
                "directory router differs from its genuine retained generation",
            ));
        }
        if latest.serial == manifest.serial
            && self.directory_router_reference(snapshot, receipt, parent)? != *latest
        {
            return Err(integrity("latest directory router generation root differs"));
        }
        if let Some(directory) = &generation.dense_prefix_segments {
            let current = self.accepted_prefix_segment_for_ordinal(
                snapshot,
                workspace,
                generation.number,
                directory.count,
                parent,
            )?;
            if self.prefix_segment_directory_reference(snapshot, &current.directory, parent)?
                != *directory
            {
                return Err(integrity(
                    "router generation lost its exact accepted fine directory",
                ));
            }
            self.check_prefix_segment_generation_binding(
                snapshot, workspace, generation, &current, parent,
            )?;
        }
        Ok(())
    }

    /// Full retained native catalog, including revisions whose live rows were GC'd.
    pub(in crate::raw_index) fn directory_router_declarations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        parent: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<(String, u64, u64), DirectoryRouterReceiptV1>> {
        let mut declarations = BTreeMap::new();
        let mut after: Option<Vec<u8>> = None;
        let mut previous = 0_u64;
        let mut previous_digest: Option<String> = None;
        loop {
            let page = crate::budgeted::metadata(snapshot, parent, |reader| {
                reader
                    .scan_prefix_page(
                        &self.keyspaces.events,
                        ScanPageRequest {
                            prefix: b"",
                            start_after: after.as_deref(),
                            max_entries: 32,
                            max_bytes: crate::MAX_JSON_BYTES + KEY_BYTES as usize + 256,
                        },
                    )
                    .map_err(storage_error)
            })?;
            for row in page.entries {
                decode_allowance(&row.value, crate::MAX_JSON_BYTES, parent)?;
                let event: crate::StoredEvent =
                    decode(&row.value, "directory router declaration event")?;
                if event.schema_version != crate::SCHEMA_VERSION
                    || row.key != event.global_commit.to_be_bytes()
                    || previous.checked_add(1) != Some(event.global_commit)
                    || event.previous_event_digest != previous_digest
                    || event.event_digest != crate::event_digest(&event)?
                    || encode(&event)? != row.value
                {
                    return Err(integrity(
                        "directory router native catalog lost a canonical accepted event",
                    ));
                }
                previous = event.global_commit;
                previous_digest = Some(event.event_digest.clone());
                if event.operation != OPERATION {
                    continue;
                }
                let reference =
                    self.prefix_publication_ref(snapshot, event.global_commit, parent)?;
                let receipt = self.directory_router_point_receipt(
                    snapshot,
                    &event.workspace_digest,
                    &reference,
                    parent,
                )?;
                self.check_directory_router_acceptance(
                    snapshot,
                    &event.workspace_digest,
                    &reference,
                    &receipt,
                    parent,
                )?;
                let manifest = &receipt.manifest;
                if self.accepted_directory_router(
                    snapshot,
                    &event.workspace_digest,
                    manifest.raw.generation,
                    manifest.serial,
                    parent,
                )? != receipt
                {
                    return Err(integrity(
                        "directory router native catalog differs from retained locator",
                    ));
                }
                if let Some(old) = &manifest.previous {
                    let key = (
                        event.workspace_digest.clone(),
                        manifest.raw.generation,
                        old.serial,
                    );
                    let predecessor = declarations.get(&key).ok_or_else(|| {
                        integrity("directory router catalog lacks an accepted predecessor")
                    })?;
                    if self.directory_router_reference(snapshot, predecessor, parent)? != *old {
                        return Err(integrity("directory router catalog predecessor differs"));
                    }
                }
                parent.charge(1, ROW_BYTES as u64).map_err(budget_error)?;
                let key = (
                    event.workspace_digest,
                    manifest.raw.generation,
                    manifest.serial,
                );
                if declarations.insert(key, receipt).is_some() {
                    return Err(integrity("duplicate native directory router revision"));
                }
            }
            let Some(next) = page.continuation else {
                break;
            };
            if after.as_ref().is_some_and(|old| &next <= old) {
                return Err(integrity(
                    "directory router native catalog made no progress",
                ));
            }
            after = Some(next);
        }
        let actual_head =
            crate::budgeted::metadata(snapshot, parent, |reader| self.global_head(reader))?;
        if previous != actual_head {
            return Err(integrity(
                "directory router catalog lost the terminal native global event",
            ));
        }
        if !declarations.is_empty() {
            self.require_directory_router_feature(snapshot, parent)?;
        }
        let mut seen = BTreeSet::new();
        let mut after: Option<Vec<u8>> = None;
        loop {
            let page = crate::budgeted::metadata(snapshot, parent, |reader| {
                reader
                    .scan_prefix_page(
                        &self.keyspaces.idempotency,
                        ScanPageRequest {
                            prefix: b"ann-directory-router/v1/",
                            start_after: after.as_deref(),
                            max_entries: 16,
                            max_bytes: ROW_BYTES * 16 + KEY_BYTES as usize * 16,
                        },
                    )
                    .map_err(storage_error)
            })?;
            for row in page.entries {
                decode_allowance(&row.value, ROW_BYTES, parent)?;
                let stored: crate::StoredIdempotency =
                    decode(&row.value, "directory router catalog locator")?;
                decode_allowance(&stored.response_bytes, MAX_PUBLICATION_BYTES, parent)?;
                let locator: RetainedDirectoryRouterLocatorV1 = decode(
                    &stored.response_bytes,
                    "directory router catalog locator acceptance",
                )?;
                locator.validate()?;
                let key = (
                    locator.workspace_digest.clone(),
                    locator.generation,
                    locator.serial,
                );
                if row.key
                    != retained_locator_key(
                        &locator.workspace_digest,
                        locator.generation,
                        locator.serial,
                    )?
                    || encode(&stored)? != row.value
                    || !declarations.contains_key(&key)
                {
                    return Err(integrity(
                        "orphan directory router locator has no exact native declaration",
                    ));
                }
                self.accepted_directory_router(
                    snapshot,
                    &locator.workspace_digest,
                    locator.generation,
                    locator.serial,
                    parent,
                )?;
                parent.charge(1, KEY_BYTES * 4).map_err(budget_error)?;
                if !seen.insert(key) {
                    return Err(integrity("duplicate retained directory router locator"));
                }
            }
            let Some(next) = page.continuation else {
                break;
            };
            if after.as_ref().is_some_and(|old| &next <= old) {
                return Err(integrity(
                    "directory router locator catalog made no progress",
                ));
            }
            after = Some(next);
        }
        if seen.len() != declarations.len() {
            return Err(integrity(
                "accepted directory router lost its retained locator",
            ));
        }
        Ok(declarations)
    }

    pub(in crate::raw_index) fn validate_directory_router_declarations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        receipts: &[&DirectoryRouterReceiptV1],
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if generation.dense_directory_router.is_some() != !receipts.is_empty() {
            return Err(integrity(
                "generation differs from accepted directory router declarations",
            ));
        }
        let mut serial = 0_u64;
        let mut previous = None;
        for receipt in receipts {
            parent.charge(1, 8192).map_err(budget_error)?;
            serial = serial
                .checked_add(1)
                .ok_or_else(|| integrity("directory router declaration serial overflow"))?;
            if receipt.manifest.serial != serial || receipt.manifest.previous != previous {
                return Err(integrity(
                    "directory router declarations are not a complete immutable sequence",
                ));
            }
            self.check_directory_router_generation_binding(
                snapshot, workspace, generation, receipt, parent,
            )?;
            previous = Some(self.directory_router_reference(snapshot, receipt, parent)?);
        }
        if previous != generation.dense_directory_router {
            return Err(integrity(
                "retained generation lost the latest accepted directory router",
            ));
        }
        Ok(())
    }
}
