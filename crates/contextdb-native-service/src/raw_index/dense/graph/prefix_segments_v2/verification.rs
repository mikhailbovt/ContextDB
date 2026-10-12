//! Immutable accepted interval joins; historical receipts are not current heads.

use super::super::prefix_v2::types::DensePrefixBaseReceiptV2;
use super::super::prefix_v2::verification::decode_allowance;
use super::*;

pub(super) fn seal_request_digest(
    database: &str,
    workspace: &str,
    request: &PrefixSegmentSealRequestV2,
) -> ServiceResult<String> {
    canonical_digest(&(types::OPERATION, database, workspace, request))
}

impl NativeService {
    pub(super) fn require_prefix_segment_feature<S: ReadSnapshot>(
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
            .ok_or_else(|| integrity("prefix segment format manifest absent"))?;
        crate::validate_manifest(&manifest, &self.database_id)?;
        if !manifest.features.contains(types::FEATURE)
            || !manifest.features.contains(prefix_v2::types::FEATURE)
            || !manifest.features.contains(dense::FEATURE)
        {
            return Err(integrity("prefix segment required format absent"));
        }
        Ok(())
    }

    pub(super) fn prefix_segment_base_reference<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        base: &DensePrefixBaseReceiptV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<PrefixSegmentBaseRefV2> {
        let publication = self.prefix_publication_ref(snapshot, base.global_commit, parent)?;
        self.check_prefix_base_acceptance(snapshot, workspace, &publication, base, parent)?;
        let bytes = segments::crypto::metered_encode(base, parent, types::ROW_BYTES)?;
        let result = PrefixSegmentBaseRefV2 {
            publication,
            receipt_digest: digest(&bytes),
            content_digest: base.manifest.content_digest,
        };
        result.validate()?;
        Ok(result)
    }

    /// Exact native acceptance and the independently retained immutable base.
    /// Work completeness is reconstructed separately by the interval verifier.
    pub(super) fn check_prefix_segment_publication<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        reference: &AcceptedPublicationRef,
        publication: &PrefixSegmentPublicationV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        publication.validate()?;
        self.check_prefix_delta_receipt(&publication.delta, parent)?;
        self.check_prefix_segment_directory_receipt(&publication.directory, parent)?;
        let (event, stored) = self.prefix_accepted_response(
            snapshot,
            workspace,
            reference,
            types::OPERATION,
            parent,
        )?;
        decode_allowance(&stored.response_bytes, MAX_PUBLICATION_BYTES, parent)?;
        let bytes = segments::crypto::metered_encode(publication, parent, MAX_PUBLICATION_BYTES)?;
        let delta = &publication.delta;
        let directory = &publication.directory;
        let manifest = &delta.manifest;
        if delta.database_id != self.database_id
            || digest_bytes(delta.workspace_id.as_bytes()) != workspace
            || delta.global_commit != reference.global_commit
            || manifest.admitted_global_commit.checked_add(1) != Some(delta.global_commit)
            || manifest.admitted_known_at.checked_add(1) != Some(event.workspace_commit)
            || bytes != stored.response_bytes
            || directory.head.content_digest
                != self.prefix_segment_directory_digest(workspace, &directory.head, parent)?
        {
            return Err(integrity("prefix segment native publication differs"));
        }
        let delta_bytes = segments::crypto::metered_encode(delta, parent, MAX_PUBLICATION_BYTES)?;
        if directory.head.latest.receipt_digest != digest(&delta_bytes) {
            return Err(integrity("prefix directory lost its full delta receipt"));
        }
        let base =
            self.accepted_prefix_base(snapshot, workspace, manifest.raw.generation, parent)?;
        if self.prefix_segment_base_reference(snapshot, workspace, &base, parent)? != manifest.base
            || base.manifest.raw.custody_version != manifest.raw.custody_version
            || base.manifest.raw.analyzer != manifest.raw.analyzer
            || base.manifest.raw.bm25 != manifest.raw.bm25
            || base.manifest.raw.authorization_epoch != manifest.raw.authorization_epoch
            || base.manifest.raw.removal_through != manifest.raw.removal_through
            || base.manifest.raw.through > manifest.raw.through
            || base.manifest.raw.projected_sources > manifest.raw.projected_sources
            || base.manifest.prefix.profile != manifest.after.profile
            || base.manifest.prefix.profile_digest != manifest.after.profile_digest
            || base.manifest.prefix.vector_space_id != manifest.after.vector_space_id
            || base.manifest.prefix.through > manifest.before.through
            || base.manifest.prefix.sources > manifest.before.sources
            || base.manifest.prefix.spans > manifest.before.spans
            || (manifest.ordinal == 1
                && (base.manifest.prefix != manifest.before
                    || base.manifest.target != manifest.before_dense))
        {
            return Err(integrity("prefix segment differs from its authentic base"));
        }
        let (before, before_manifest) =
            self.prefix_dense_target_binding(snapshot, workspace, &manifest.before_dense, parent)?;
        let (after, after_manifest) =
            self.prefix_dense_target_binding(snapshot, workspace, &manifest.target_dense, parent)?;
        if before_manifest != manifest.before
            || after_manifest != manifest.after
            || before.generation != manifest.raw.generation
            || after.generation != manifest.raw.generation
            || before.authorization_epoch != manifest.raw.authorization_epoch
            || after.authorization_epoch != manifest.raw.authorization_epoch
            || after.raw_through != manifest.raw.through
            || after.raw_sources != manifest.raw.projected_sources
            || before.raw_through > after.raw_through
            || before.raw_sources > after.raw_sources
        {
            return Err(integrity("prefix segment accepted dense states differ"));
        }
        // Rebuild the exact operator request from owner-accepted state. A valid
        // historical response may never be attached to a different predecessor.
        let request = PrefixSegmentSealRequestV2 {
            generation: manifest.raw.generation,
            previous: directory.head.previous.clone(),
            target: after,
        };
        if seal_request_digest(&self.database_id, workspace, &request)? != reference.request_digest
        {
            return Err(integrity(
                "prefix segment accepted request identity differs",
            ));
        }
        self.require_prefix_segment_feature(snapshot, parent)
    }

    pub(super) fn accepted_prefix_segment_publication<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        reference: &AcceptedPublicationRef,
        parent: &mut QueryBudget,
    ) -> ServiceResult<PrefixSegmentPublicationV2> {
        let (_, stored) = self.prefix_accepted_response(
            snapshot,
            workspace,
            reference,
            types::OPERATION,
            parent,
        )?;
        decode_allowance(&stored.response_bytes, MAX_PUBLICATION_BYTES, parent)?;
        let publication = decode(
            &stored.response_bytes,
            "accepted prefix segment publication",
        )?;
        self.check_prefix_segment_publication(
            snapshot,
            workspace,
            reference,
            &publication,
            parent,
        )?;
        Ok(publication)
    }

    pub(crate) fn prefix_segment_directory_reference<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        receipt: &PrefixSegmentDirectoryReceiptV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<PrefixSegmentDirectoryRefV2> {
        let workspace = digest_bytes(receipt.workspace_id.as_bytes());
        let reference = self.prefix_publication_ref(snapshot, receipt.global_commit, parent)?;
        let publication =
            self.accepted_prefix_segment_publication(snapshot, &workspace, &reference, parent)?;
        if &publication.directory != receipt {
            return Err(integrity(
                "prefix directory differs from retained acceptance",
            ));
        }
        Ok(PrefixSegmentDirectoryRefV2 {
            count: receipt.head.count,
            global_commit: reference.global_commit,
            request_digest: reference.request_digest,
            response_digest: reference.response_digest,
            content_digest: receipt.head.content_digest,
        })
    }

    /// This locator and its primary accepted response outlive generation rows.
    pub(crate) fn accepted_prefix_segment_for_ordinal<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        ordinal: u64,
        parent: &mut QueryBudget,
    ) -> ServiceResult<PrefixSegmentPublicationV2> {
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let key = retained_locator_key(workspace, generation, ordinal)?;
        let stored: crate::StoredIdempotency = self
            .prefix_read(snapshot, &self.keyspaces.idempotency, &key, parent)?
            .ok_or_else(|| integrity("retained prefix segment locator absent"))?;
        decode_allowance(&stored.response_bytes, MAX_PUBLICATION_BYTES, parent)?;
        let locator: RetainedPrefixSegmentLocatorV2 =
            decode(&stored.response_bytes, "retained prefix segment locator")?;
        self.check_retained_prefix_segment_locator(workspace, &locator, parent)?;
        if locator.workspace_digest != workspace
            || locator.generation != generation
            || locator.ordinal != ordinal
            || stored.schema_version != crate::SCHEMA_VERSION
            || stored.operation != LOCATOR_OPERATION
            || stored.request_digest != canonical_digest(&locator)?
            || stored.response_digest != digest_bytes(&stored.response_bytes)
            || encode(&locator)? != stored.response_bytes
        {
            return Err(integrity("prefix segment retained locator binding differs"));
        }
        let publication = self.accepted_prefix_segment_publication(
            snapshot,
            workspace,
            &locator.publication,
            parent,
        )?;
        if publication.delta.manifest.raw.generation != generation
            || publication.delta.manifest.ordinal != ordinal
        {
            return Err(integrity("prefix segment retained ordinal differs"));
        }
        Ok(publication)
    }

    pub(super) fn accepted_current_prefix_segment<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_id: &str,
        generation: &Generation,
        parent: &mut QueryBudget,
    ) -> ServiceResult<PrefixSegmentPublicationV2> {
        let workspace = digest_bytes(workspace_id.as_bytes());
        let reference = generation
            .dense_prefix_segments
            .as_ref()
            .ok_or_else(stale_index)?;
        let world = self.current_prefix_segment_heads(snapshot, workspace_id, parent)?;
        if world
            .prefix_segment_heads
            .as_ref()
            .and_then(|roots| roots.get(&generation.number))
            != Some(reference)
        {
            return Err(integrity(
                "prefix generation differs from current certified directory",
            ));
        }
        let publication = self.accepted_prefix_segment_for_ordinal(
            snapshot,
            &workspace,
            generation.number,
            reference.count,
            parent,
        )?;
        if self.prefix_segment_directory_reference(snapshot, &publication.directory, parent)?
            != *reference
        {
            return Err(integrity(
                "current prefix directory differs from retained head",
            ));
        }
        let live: PrefixSegmentDirectoryReceiptV2 = self
            .prefix_read(
                snapshot,
                &self.keyspaces.continuous,
                &directory_head_key(&workspace, generation.number)?,
                parent,
            )?
            .ok_or_else(|| integrity("live prefix segment directory absent"))?;
        self.check_prefix_segment_generation_binding(
            snapshot,
            &workspace,
            generation,
            &publication,
            parent,
        )?;
        if live != publication.directory {
            return Err(integrity(
                "live prefix segment head differs from accepted current head",
            ));
        }
        Ok(publication)
    }

    /// Administrative declarations remain independent of reclaimed live rows.
    pub(in crate::raw_index) fn prefix_segment_declarations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        parent: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<(String, u64, u64), PrefixSegmentPublicationV2>> {
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
                    decode(&row.value, "prefix segment declaration event")?;
                if event.schema_version != crate::SCHEMA_VERSION
                    || row.key != event.global_commit.to_be_bytes()
                    || previous.checked_add(1) != Some(event.global_commit)
                    || event.previous_event_digest != previous_digest
                    || event.event_digest != crate::event_digest(&event)?
                    || encode(&event)? != row.value
                {
                    return Err(integrity(
                        "prefix interval declaration journal has a missing or changed event",
                    ));
                }
                previous = event.global_commit;
                previous_digest = Some(event.event_digest.clone());
                if event.operation != types::OPERATION {
                    continue;
                }
                let reference =
                    self.prefix_publication_ref(snapshot, event.global_commit, parent)?;
                let publication = self.accepted_prefix_segment_publication(
                    snapshot,
                    &event.workspace_digest,
                    &reference,
                    parent,
                )?;
                let manifest = &publication.delta.manifest;
                if self.accepted_prefix_segment_for_ordinal(
                    snapshot,
                    &event.workspace_digest,
                    manifest.raw.generation,
                    manifest.ordinal,
                    parent,
                )? != publication
                {
                    return Err(integrity(
                        "prefix interval declaration differs from retained locator",
                    ));
                }
                parent
                    .charge(1, types::ROW_BYTES as u64)
                    .map_err(budget_error)?;
                let key = (
                    event.workspace_digest,
                    manifest.raw.generation,
                    manifest.ordinal,
                );
                if declarations.insert(key, publication).is_some() {
                    return Err(integrity(
                        "raw generation has duplicate accepted prefix interval ordinals",
                    ));
                }
            }
            let Some(next) = page.continuation else {
                break;
            };
            if after.as_ref().is_some_and(|old| &next <= old) {
                return Err(integrity(
                    "prefix interval declaration scan made no progress",
                ));
            }
            after = Some(next);
        }
        if !declarations.is_empty() {
            self.require_prefix_segment_feature(snapshot, parent)?;
        }
        // Any independently retained locator must have its exact accepted native
        // declaration, including after every generation row has been reclaimed.
        let mut seen = BTreeSet::new();
        let mut after: Option<Vec<u8>> = None;
        loop {
            let page = crate::budgeted::metadata(snapshot, parent, |reader| {
                reader
                    .scan_prefix_page(
                        &self.keyspaces.idempotency,
                        ScanPageRequest {
                            prefix: b"ann-prefix-segment/v2/",
                            start_after: after.as_deref(),
                            max_entries: 16,
                            max_bytes: types::ROW_BYTES * 16 + KEY_BYTES as usize * 16,
                        },
                    )
                    .map_err(storage_error)
            })?;
            for row in page.entries {
                decode_allowance(&row.value, types::ROW_BYTES, parent)?;
                let stored: crate::StoredIdempotency =
                    decode(&row.value, "prefix interval locator declaration")?;
                decode_allowance(&stored.response_bytes, MAX_PUBLICATION_BYTES, parent)?;
                let locator: RetainedPrefixSegmentLocatorV2 = decode(
                    &stored.response_bytes,
                    "prefix interval retained declaration",
                )?;
                locator.validate()?;
                let key = (
                    locator.workspace_digest.clone(),
                    locator.generation,
                    locator.ordinal,
                );
                let expected = retained_locator_key(
                    &locator.workspace_digest,
                    locator.generation,
                    locator.ordinal,
                )?;
                if row.key != expected
                    || encode(&stored)? != row.value
                    || !declarations.contains_key(&key)
                {
                    return Err(integrity(
                        "orphan prefix interval locator lacks an exact accepted declaration",
                    ));
                }
                self.accepted_prefix_segment_for_ordinal(
                    snapshot,
                    &locator.workspace_digest,
                    locator.generation,
                    locator.ordinal,
                    parent,
                )?;
                parent.charge(1, KEY_BYTES * 4).map_err(budget_error)?;
                if !seen.insert(key) {
                    return Err(integrity("duplicate retained prefix interval locator"));
                }
            }
            let Some(next) = page.continuation else {
                break;
            };
            if after.as_ref().is_some_and(|old| &next <= old) {
                return Err(integrity("prefix interval locator scan made no progress"));
            }
            after = Some(next);
        }
        if seen.len() != declarations.len() {
            return Err(integrity(
                "accepted prefix interval lost its retained locator",
            ));
        }
        Ok(declarations)
    }
}
