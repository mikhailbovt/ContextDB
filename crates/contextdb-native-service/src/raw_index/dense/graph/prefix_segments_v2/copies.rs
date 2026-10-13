//! Administrative immutable copy checks. Live siblings are not acceptance proofs.
//! Source ownership is supplied by the actual captured envelope and retained controls.

use super::crypto::{metered_encode, metered_json_len};
use super::types::{
    self, PrefixDeltaReceiptV2, PrefixSegCohortV2, PrefixSegMemberV2, PrefixSegNodeV2,
    PrefixSegmentDirectoryReceiptV2, PrefixSegmentPublicationV2,
};
use crate::{
    NativeService, decode, digest_bytes, integrity,
    raw_index::{Generation, IndexedOriginal, budget_error},
};
use contextdb_core::{ObservationId, RawSource};
use contextdb_recall::QueryBudget;
use contextdb_service::ServiceResult;
use contextdb_storage::ReadSnapshot;
use serde::{Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
enum CopyKind {
    Directory,
    Receipt,
    Member,
    Cohort,
    Node,
}

/// Borrow the address only. Final helper equality rejects alternate spelling,
/// suffixes and row identities before attribution can be returned.
fn copy_address(key: &[u8], generation: u64) -> ServiceResult<(&str, Option<u64>, CopyKind)> {
    let text =
        std::str::from_utf8(key).map_err(|_| integrity("prefix segment copy key is not UTF-8"))?;
    let mut parts = text.split('/');
    if parts.next() != Some("raw") || parts.next() != Some("g") {
        return Err(integrity("prefix segment copy namespace differs"));
    }
    let workspace = parts
        .next()
        .ok_or_else(|| integrity("prefix segment copy workspace absent"))?;
    let number = parts
        .next()
        .ok_or_else(|| integrity("prefix segment copy generation absent"))?;
    if !types::valid_hex(workspace)
        || number.len() != 20
        || !number.bytes().all(|b| b.is_ascii_digit())
        || number.parse::<u64>().ok() != Some(generation)
        || parts.next() != Some("dense")
    {
        return Err(integrity(
            "prefix segment copy generation namespace differs",
        ));
    }
    match parts.next() {
        Some("prefix-segments-v2") if parts.next() == Some("head") && parts.next().is_none() => {
            Ok((workspace, None, CopyKind::Directory))
        }
        Some("prefix-segment-v2") => {
            let text = parts
                .next()
                .ok_or_else(|| integrity("prefix segment copy ordinal absent"))?;
            let ordinal = u64::from_str_radix(text, 16)
                .ok()
                .filter(|n| {
                    *n > 0
                        && text.len() == 16
                        && text
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
                .ok_or_else(|| integrity("prefix segment copy ordinal differs"))?;
            let kind = match parts.next() {
                Some("receipt") if parts.next().is_none() => CopyKind::Receipt,
                Some("member") if parts.next().is_some() && parts.next().is_none() => {
                    CopyKind::Member
                }
                Some("cohort") if parts.next().is_some() && parts.next().is_none() => {
                    CopyKind::Cohort
                }
                Some("node") if parts.next().is_some() && parts.next().is_none() => CopyKind::Node,
                _ => return Err(integrity("unknown prefix segment copy row")),
            };
            Ok((workspace, Some(ordinal), kind))
        }
        _ => Err(integrity("unknown prefix segment copy namespace")),
    }
}

fn decode_copy<T: DeserializeOwned + Serialize>(
    value: &[u8],
    parent: &mut QueryBudget,
) -> ServiceResult<T> {
    // The caller prepays bounded decode allocations before reaching this helper.
    let row: T = decode(value, "canonical prefix segment copy")?;
    if metered_encode(&row, parent, types::ROW_BYTES)? != value {
        return Err(integrity("prefix segment copy encoding is not canonical"));
    }
    Ok(row)
}

impl NativeService {
    /// Verify historical copy attribution under the supplied reclamation budget.
    /// This grants neither original disclosure nor a current serving directory.
    /// Member checks retain the published-prefix captured-envelope requirement;
    /// a pruned body is never replaced with an invented source version.
    pub(in crate::raw_index) fn verify_dense_prefix_segment_copy<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        generation: &Generation,
        key: &[u8],
        value: &[u8],
        parent: &mut QueryBudget,
    ) -> ServiceResult<Option<ObservationId>> {
        parent.check().map_err(budget_error)?;
        if key.len() > types::KEY_BYTES as usize || value.len() > types::ROW_BYTES {
            return Err(integrity("prefix segment copy exceeds its row/key bound"));
        }
        parent
            .charge(
                key.len() as u64 + value.len() as u64 * 8 + 1,
                key.len() as u64 * 4 + value.len() as u64 * 16 + 8192,
            )
            .map_err(budget_error)?;
        let (workspace, ordinal, kind) = copy_address(key, generation.number)?;
        self.require_prefix_segment_feature(snapshot, parent)?;
        if matches!(kind, CopyKind::Directory) {
            let row: PrefixSegmentDirectoryReceiptV2 = decode_copy(value, parent)?;
            parent.charge(1, types::KEY_BYTES).map_err(budget_error)?;
            if key != types::directory_head_key(workspace, generation.number)? {
                return Err(integrity("prefix segment directory copy key differs"));
            }
            self.check_prefix_segment_directory_receipt(&row, parent)?;
            let accepted = self.accepted_prefix_segment_for_ordinal(
                snapshot,
                workspace,
                generation.number,
                row.head.count,
                parent,
            )?;
            self.prefix_segment_copy_generation(
                snapshot, generation, workspace, &accepted, parent,
            )?;
            if row != accepted.directory
                || generation.dense_prefix_segments.as_ref()
                    != Some(&self.prefix_segment_directory_reference(snapshot, &row, parent)?)
            {
                return Err(integrity(
                    "prefix segment directory copy differs from its generation head",
                ));
            }
            return Ok(None);
        }
        let ordinal = ordinal.ok_or_else(|| integrity("prefix segment copy ordinal absent"))?;
        let accepted = self.accepted_prefix_segment_for_ordinal(
            snapshot,
            workspace,
            generation.number,
            ordinal,
            parent,
        )?;
        self.prefix_segment_copy_generation(snapshot, generation, workspace, &accepted, parent)?;
        let manifest = &accepted.delta.manifest;
        parent.charge(1, types::KEY_BYTES).map_err(budget_error)?;
        match kind {
            CopyKind::Receipt => {
                let row: PrefixDeltaReceiptV2 = decode_copy(value, parent)?;
                if key != types::delta_receipt_key(workspace, generation.number, ordinal)?
                    || row != accepted.delta
                {
                    return Err(integrity(
                        "prefix delta receipt copy differs from retained acceptance",
                    ));
                }
                self.check_prefix_delta_receipt(&row, parent)?;
                Ok(None)
            }
            CopyKind::Member => {
                let row: PrefixSegMemberV2 = decode_copy(value, parent)?;
                if key
                    != types::segment_member_key(
                        workspace,
                        generation.number,
                        ordinal,
                        row.representation_id,
                    )?
                {
                    return Err(integrity("prefix segment member copy key differs"));
                }
                self.check_prefix_segment_member(workspace, manifest, &row, parent)?;
                let original =
                    self.load_captured_original_with_budget(snapshot, row.source.event_id, parent)?;
                let version_bytes = original
                    .event
                    .source_version
                    .as_ref()
                    .map_or(0, String::len);
                // Covers actual RawSource strings, full parent tree and workspace
                // formatting/hash before constructing owned attribution metadata.
                let metadata_bytes = metered_json_len(
                    &(
                        &original.event.source_version,
                        &original.event.parent_event_ids,
                    ),
                    parent,
                    crate::MAX_JSON_BYTES,
                )?;
                parent
                    .charge(
                        original.event.parent_event_ids.len() as u64 + metadata_bytes as u64 + 2,
                        (original.event.parent_event_ids.len() as u64 + 1) * 2048
                            + metadata_bytes as u64 * 4
                            + version_bytes as u64 * 8
                            + 8192,
                    )
                    .map_err(budget_error)?;
                let source = RawSource::from(&original.event);
                if source != row.source
                    || original.receipt.event_id != row.source.event_id
                    || original.receipt.workspace_commit != row.commit
                    || original.receipt.event_digest != row.event_digest
                    || digest_bytes(original.event.workspace_id.to_string().as_bytes()) != workspace
                {
                    return Err(integrity(
                        "prefix segment member copy differs from actual captured source",
                    ));
                }
                let mut parents: BTreeSet<_> =
                    original.event.parent_event_ids.iter().copied().collect();
                if let Some(superseded) = original.event.supersedes_event_id {
                    parents.insert(superseded);
                }
                let document = IndexedOriginal {
                    source,
                    event_digest: original.receipt.event_digest,
                    commit: original.receipt.workspace_commit,
                    policy_domain: row.policy_domain,
                    lexical_complete: false,
                    first_terms: BTreeMap::new(),
                    parents,
                };
                self.verify_projected_causal_metadata(snapshot, workspace, &document, parent)?;
                Ok(Some(document.source.event_id))
            }
            CopyKind::Cohort => {
                let row: PrefixSegCohortV2 = decode_copy(value, parent)?;
                if key
                    != types::segment_cohort_key(
                        workspace,
                        generation.number,
                        ordinal,
                        &row.policy_domain,
                    )?
                {
                    return Err(integrity("prefix segment cohort copy key differs"));
                }
                self.check_prefix_segment_cohort(workspace, manifest, &row, parent)?;
                Ok(None)
            }
            CopyKind::Node => {
                let row: PrefixSegNodeV2 = decode_copy(value, parent)?;
                if key
                    != types::segment_node_key(
                        workspace,
                        generation.number,
                        ordinal,
                        row.representation_id,
                    )?
                {
                    return Err(integrity("prefix segment node copy key differs"));
                }
                self.check_prefix_segment_node(workspace, manifest, &row, parent)?;
                Ok(None)
            }
            CopyKind::Directory => {
                Err(integrity("prefix segment directory copy namespace differs"))
            }
        }
    }

    fn prefix_segment_copy_generation<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        generation: &Generation,
        workspace: &str,
        accepted: &PrefixSegmentPublicationV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let bytes = metered_json_len(&(generation, accepted), parent, types::ROW_BYTES * 2)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 4 + 8192)
            .map_err(budget_error)?;
        accepted.validate()?;
        let manifest = &accepted.delta.manifest;
        let raw = &manifest.raw;
        let base = generation
            .dense_prefix_base
            .as_ref()
            .ok_or_else(|| integrity("prefix segment copy immutable base absent"))?;
        let head = generation
            .dense_prefix_segments
            .as_ref()
            .ok_or_else(|| integrity("prefix segment copy accepted directory absent"))?;
        let latest = generation
            .dense
            .as_ref()
            .ok_or_else(|| integrity("prefix segment copy accepted dense profile absent"))?;
        base.validate()?;
        head.validate()?;
        latest.validate(generation.through)?;
        parent
            .charge(accepted.delta.workspace_id.len() as u64 + 1, 128)
            .map_err(budget_error)?;
        if accepted.delta.database_id != self.database_id
            || digest_bytes(accepted.delta.workspace_id.as_bytes()) != workspace
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
            || generation.dense_graph.is_some()
            || generation.dense_segments.is_some()
            || base.global_commit != manifest.base.publication.global_commit
            || base.request_digest != manifest.base.publication.request_digest
            || base.response_digest != manifest.base.publication.response_digest
            || base.receipt_digest != manifest.base.receipt_digest
            || base.content_digest != manifest.base.content_digest
            || manifest.ordinal > head.count
            || accepted.delta.global_commit > head.global_commit
            || manifest.after.profile != latest.profile
            || manifest.after.profile_digest != latest.profile_digest
            || manifest.after.vector_space_id != latest.vector_space_id
            || manifest.after.through > latest.through
            || manifest.after.sources > latest.sources
            || manifest.after.embedded_sources > latest.embedded_sources
            || manifest.after.omitted_sources > latest.omitted_sources
            || manifest.after.spans > latest.spans
            || (manifest.after.through == latest.through && manifest.after != *latest)
            || (manifest.ordinal == head.count
                && self.prefix_segment_directory_reference(
                    snapshot,
                    &accepted.directory,
                    parent,
                )? != *head)
        {
            return Err(integrity(
                "prefix segment copy differs from its real frozen generation",
            ));
        }
        Ok(())
    }
}
