//! Administrative verification of immutable segment copies during reclamation.
//! Accepted ordinal locators survive live graph/head rows; source versions come
//! from the actual captured envelope, never a fabricated recovery value.

use super::types::{
    self, DenseDeltaReceipt, DenseSegmentDirectoryReceipt, DenseSegmentPublication, SegCohort,
    SegMember, SegNode,
};
use crate::raw_index::{Generation, IndexedOriginal, budget_error};
use crate::{NativeService, decode, digest_bytes, integrity};
use contextdb_core::{ObservationId, RawSource};
use contextdb_recall::QueryBudget;
use contextdb_service::ServiceResult;
use contextdb_storage::ReadSnapshot;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
enum CopyKind {
    Directory,
    Receipt,
    Member,
    Cohort,
    Node,
}

/// Parse borrowed key components only; canonical helper equality below rejects
/// alternate numeric spelling, extra suffixes and foreign row identities.
fn copy_address(key: &[u8], generation: u64) -> ServiceResult<(&str, Option<u64>, CopyKind)> {
    let text = std::str::from_utf8(key).map_err(|_| integrity("segment copy key is not UTF-8"))?;
    let mut parts = text.split('/');
    if parts.next() != Some("raw") || parts.next() != Some("g") {
        return Err(integrity("segment copy namespace differs"));
    }
    let workspace = parts
        .next()
        .ok_or_else(|| integrity("segment copy workspace is absent"))?;
    let number = parts
        .next()
        .ok_or_else(|| integrity("segment copy generation is absent"))?;
    if !types::valid_hex(workspace)
        || number.len() != 20
        || !number.bytes().all(|byte| byte.is_ascii_digit())
        || number.parse::<u64>().ok() != Some(generation)
        || parts.next() != Some("dense")
        || parts.next() != Some("graph")
    {
        return Err(integrity("segment copy generation namespace differs"));
    }
    match parts.next() {
        Some("segments") if parts.next() == Some("head") && parts.next().is_none() => {
            Ok((workspace, None, CopyKind::Directory))
        }
        Some("segment") => {
            let number = parts
                .next()
                .ok_or_else(|| integrity("segment copy ordinal is absent"))?;
            let ordinal = u64::from_str_radix(number, 16)
                .ok()
                .filter(|ordinal| *ordinal > 0 && number.len() == 16)
                .ok_or_else(|| integrity("segment copy ordinal differs"))?;
            let kind = match parts.next() {
                Some("receipt") if parts.next().is_none() => CopyKind::Receipt,
                Some("member") if parts.next().is_some() && parts.next().is_none() => {
                    CopyKind::Member
                }
                Some("cohort") if parts.next().is_some() && parts.next().is_none() => {
                    CopyKind::Cohort
                }
                Some("node") if parts.next().is_some() && parts.next().is_none() => CopyKind::Node,
                _ => return Err(integrity("unknown native segment copy row")),
            };
            Ok((workspace, Some(ordinal), kind))
        }
        _ => Err(integrity("unknown native segment copy namespace")),
    }
}

impl NativeService {
    /// The reclamation owner admits this operation. This verifies stored copy
    /// attribution and seals, not source disclosure or a current serving head.
    pub(in crate::raw_index) fn verify_dense_segment_copy<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        generation: &Generation,
        key: &[u8],
        value: &[u8],
        parent: &mut QueryBudget,
    ) -> ServiceResult<Option<ObservationId>> {
        parent.check().map_err(budget_error)?;
        if key.len() > types::KEY_BYTES as usize || value.len() > types::ROW_BYTES {
            return Err(integrity("segment copy exceeds bounded row or key size"));
        }
        parent
            .charge(1, key.len() as u64 * 4 + value.len() as u64 * 8 + 8192)
            .map_err(budget_error)?;
        let (workspace, ordinal, kind) = copy_address(key, generation.number)?;
        let format: crate::Manifest = self
            .graph_read(
                snapshot,
                &self.keyspaces.meta,
                crate::META_MANIFEST_KEY,
                parent,
            )?
            .ok_or_else(|| integrity("segment copy format manifest is absent"))?;
        if !format.features.contains(types::FEATURE)
            || !format.features.contains(super::super::FEATURE)
            || !format.features.contains(crate::raw_index::dense::FEATURE)
            || !format.features.contains(crate::raw_index::bm25::FEATURE)
        {
            return Err(integrity("segment copy required format feature is absent"));
        }

        if matches!(kind, CopyKind::Directory) {
            let receipt: DenseSegmentDirectoryReceipt = decode(value, "segment directory copy")?;
            parent.charge(1, types::KEY_BYTES).map_err(budget_error)?;
            if key != types::directory_head_key(workspace, generation.number)? {
                return Err(integrity("segment directory copy key differs"));
            }
            self.check_segment_directory_receipt(&receipt, parent)?;
            let accepted = self.accepted_segment_for_ordinal(
                snapshot,
                workspace,
                generation.number,
                receipt.head.count,
                parent,
            )?;
            self.segment_copy_generation(generation, workspace, &accepted, parent)?;
            if receipt != accepted.directory {
                return Err(integrity(
                    "segment directory copy differs from accepted publication",
                ));
            }
            return Ok(None);
        }

        let ordinal = ordinal.ok_or_else(|| integrity("segment copy ordinal is absent"))?;
        let accepted = self.accepted_segment_for_ordinal(
            snapshot,
            workspace,
            generation.number,
            ordinal,
            parent,
        )?;
        self.segment_copy_generation(generation, workspace, &accepted, parent)?;
        let manifest = &accepted.delta.manifest;
        match kind {
            CopyKind::Receipt => {
                let receipt: DenseDeltaReceipt = decode(value, "segment delta receipt copy")?;
                parent.charge(1, types::KEY_BYTES).map_err(budget_error)?;
                if key != types::delta_receipt_key(workspace, generation.number, ordinal)? {
                    return Err(integrity("segment delta receipt copy key differs"));
                }
                self.check_delta_receipt(&receipt, parent)?;
                if receipt != accepted.delta {
                    return Err(integrity(
                        "segment delta receipt copy differs from accepted publication",
                    ));
                }
                Ok(None)
            }
            CopyKind::Member => {
                let row: SegMember = decode(value, "segment member copy")?;
                parent.charge(1, types::KEY_BYTES).map_err(budget_error)?;
                if key
                    != types::segment_member_key(
                        workspace,
                        generation.number,
                        ordinal,
                        row.representation_id,
                    )?
                {
                    return Err(integrity("segment member copy key differs"));
                }
                self.check_segment_member(workspace, manifest, &row, parent)?;
                let original =
                    self.load_captured_original_with_budget(snapshot, row.source.event_id, parent)?;
                let version_bytes = original
                    .event
                    .source_version
                    .as_ref()
                    .map_or(0, String::len);
                parent
                    .charge(
                        original.event.parent_event_ids.len() as u64 + 2,
                        (original.event.parent_event_ids.len() as u64 + 1) * 2048
                            + version_bytes as u64 * 8
                            + row.policy_domain.len() as u64 * 4
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
                        "segment member copy differs from actual captured source",
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
                let row: SegCohort = decode(value, "segment cohort copy")?;
                parent.charge(1, types::KEY_BYTES).map_err(budget_error)?;
                if key
                    != types::segment_cohort_key(
                        workspace,
                        generation.number,
                        ordinal,
                        &row.policy_domain,
                    )?
                {
                    return Err(integrity("segment cohort copy key differs"));
                }
                self.check_segment_cohort(workspace, manifest, &row, parent)?;
                Ok(None)
            }
            CopyKind::Node => {
                let row: SegNode = decode(value, "segment node copy")?;
                parent.charge(1, types::KEY_BYTES).map_err(budget_error)?;
                if key
                    != types::segment_node_key(
                        workspace,
                        generation.number,
                        ordinal,
                        row.representation_id,
                    )?
                {
                    return Err(integrity("segment node copy key differs"));
                }
                self.check_segment_node(workspace, manifest, &row, parent)?;
                Ok(None)
            }
            CopyKind::Directory => Err(integrity("segment directory copy namespace differs")),
        }
    }

    fn segment_copy_generation(
        &self,
        generation: &Generation,
        workspace: &str,
        accepted: &DenseSegmentPublication,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent.charge(1, 8192).map_err(budget_error)?;
        let manifest = &accepted.delta.manifest;
        let binding = &manifest.binding;
        let base = generation
            .dense_graph
            .as_ref()
            .ok_or_else(|| integrity("segment copy immutable base is absent"))?;
        let latest = generation
            .dense
            .as_ref()
            .ok_or_else(|| integrity("segment copy accepted dense profile is absent"))?;
        if accepted.delta.database_id != self.database_id
            || digest_bytes(accepted.delta.workspace_id.as_bytes()) != workspace
            || binding.generation != generation.number
            || binding.custody_version != generation.custody_version
            || binding.analyzer != generation.analyzer
            || generation.bm25.as_ref() != Some(&binding.bm25)
            || binding.authorization_epoch != generation.authorization_epoch
            || binding.removal_through != generation.removal_through
            || binding.raw_through > generation.through
            || binding.raw_sources > generation.projected_sources
            || manifest.base.graph_digest != base.content_digest
            || manifest.before.through < base.dense.through
            || manifest.before.profile != base.dense.profile
            || manifest.after.profile != latest.profile
            || manifest.after.profile_digest != latest.profile_digest
            || manifest.after.vector_space_id != latest.vector_space_id
            || manifest.after.through > latest.through
            || manifest.after.sources > latest.sources
            || manifest.after.embedded_sources > latest.embedded_sources
            || manifest.after.omitted_sources > latest.omitted_sources
            || manifest.after.spans > latest.spans
        {
            return Err(integrity("segment copy differs from its frozen generation"));
        }
        Ok(())
    }
}
