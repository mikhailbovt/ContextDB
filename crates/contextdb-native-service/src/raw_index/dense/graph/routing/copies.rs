//! Historical shared routing-copy checks. No source owner, disclosure or key-erasure claim.

use super::crypto::{metered_encode, metered_json_len};
use super::types::*;
use crate::{
    NativeService, decode, integrity,
    raw_index::{Generation, budget_error},
};
use contextdb_recall::QueryBudget;
use contextdb_service::ServiceResult;
use contextdb_storage::ReadSnapshot;
use serde::{Serialize, de::DeserializeOwned};

#[derive(Clone, Copy)]
enum CopyKind {
    Head,
    Receipt,
    Member,
    Vector,
    Cohort,
    Node,
}
fn copy_address(key: &[u8], generation: u64) -> ServiceResult<(&str, Option<u64>, CopyKind)> {
    let text = std::str::from_utf8(key).map_err(|_| integrity("router copy key is not UTF-8"))?;
    let mut parts = text.split('/');
    if parts.next() != Some("raw") || parts.next() != Some("g") {
        return Err(integrity("router copy namespace differs"));
    }
    let workspace = parts
        .next()
        .ok_or_else(|| integrity("router copy workspace absent"))?;
    let number = parts
        .next()
        .ok_or_else(|| integrity("router copy generation absent"))?;
    if !valid_hex(workspace)
        || number.len() != 20
        || !number.bytes().all(|b| b.is_ascii_digit())
        || number.parse::<u64>().ok() != Some(generation)
        || parts.next() != Some("dense")
    {
        return Err(integrity("router copy generation namespace differs"));
    }
    match parts.next() {
        Some("directory-routers-v1") if parts.next() == Some("head") && parts.next().is_none() => {
            Ok((workspace, None, CopyKind::Head))
        }
        Some("directory-router-v1") => {
            let number = parts
                .next()
                .ok_or_else(|| integrity("router copy serial absent"))?;
            let serial = u64::from_str_radix(number, 16)
                .ok()
                .filter(|n| {
                    *n > 0
                        && number.len() == 16
                        && number
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
                .ok_or_else(|| integrity("router copy serial differs"))?;
            let kind = match parts.next() {
                Some("receipt") if parts.next().is_none() => CopyKind::Receipt,
                Some("member") if parts.next().is_some() && parts.next().is_none() => {
                    CopyKind::Member
                }
                Some("vector") if parts.next().is_some() && parts.next().is_none() => {
                    CopyKind::Vector
                }
                Some("cohort") if parts.next().is_some() && parts.next().is_none() => {
                    CopyKind::Cohort
                }
                Some("node") if parts.next().is_some() && parts.next().is_none() => CopyKind::Node,
                _ => return Err(integrity("unknown directory router copy row")),
            };
            Ok((workspace, Some(serial), kind))
        }
        _ => Err(integrity("unknown directory router copy namespace")),
    }
}
fn decode_copy<T: DeserializeOwned + Serialize>(
    value: &[u8],
    parent: &mut QueryBudget,
) -> ServiceResult<T> {
    // The caller has already admitted this bounded decode before allocation.
    let row: T = decode(value, "canonical directory router copy")?;
    if metered_encode(&row, parent, ROW_BYTES)? != value {
        return Err(integrity("directory router copy is not canonical"));
    }
    Ok(row)
}

impl NativeService {
    /// Every row is SharedMetadata with owner None. Saved authentic generations
    /// may be checked after full GC without a physical sibling or current map.
    pub(in crate::raw_index) fn verify_dense_directory_router_copy<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        generation: &Generation,
        key: &[u8],
        value: &[u8],
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent.check().map_err(budget_error)?;
        if key.len() > KEY_BYTES as usize || value.len() > ROW_BYTES {
            return Err(integrity("router copy exceeds its row/key bound"));
        }
        parent
            .charge(
                key.len() as u64 + value.len() as u64 * 8 + 1,
                key.len() as u64 * 4 + value.len() as u64 * 16 + 8192,
            )
            .map_err(budget_error)?;
        let (workspace, serial, kind) = copy_address(key, generation.number)?;
        self.require_directory_router_feature(snapshot, parent)?;
        if matches!(kind, CopyKind::Head) {
            let row: DirectoryRouterReceiptV1 = decode_copy(value, parent)?;
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            if key != head_key(workspace, generation.number)? {
                return Err(integrity("router head copy key differs"));
            }
            let accepted = self.accepted_directory_router(
                snapshot,
                workspace,
                generation.number,
                row.manifest.serial,
                parent,
            )?;
            self.router_copy_generation(snapshot, workspace, generation, &accepted, parent)?;
            if row != accepted
                || generation.dense_directory_router.as_ref()
                    != Some(&self.directory_router_reference(snapshot, &row, parent)?)
            {
                return Err(integrity(
                    "router head copy differs from saved latest generation root",
                ));
            }
            return Ok(());
        }
        let serial = serial.ok_or_else(|| integrity("router immutable copy serial absent"))?;
        let accepted =
            self.accepted_directory_router(snapshot, workspace, generation.number, serial, parent)?;
        self.router_copy_generation(snapshot, workspace, generation, &accepted, parent)?;
        let manifest = &accepted.manifest;
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        match kind {
            CopyKind::Receipt => {
                let row: DirectoryRouterReceiptV1 = decode_copy(value, parent)?;
                if key != receipt_key(workspace, generation.number, serial)? || row != accepted {
                    return Err(integrity(
                        "router receipt copy differs from retained native acceptance",
                    ));
                }
                self.check_directory_router_receipt(&row, parent)
            }
            CopyKind::Member => {
                let row: DirectoryRouterMemberV1 = decode_copy(value, parent)?;
                if key != member_key(workspace, generation.number, serial, row.representation_id)? {
                    return Err(integrity("router member copy key differs"));
                }
                self.check_router_member(workspace, manifest, &row, parent)?;
                self.check_router_copy_fine_path(snapshot, workspace, manifest, &row, parent)
            }
            CopyKind::Vector => {
                let row: DirectoryRouterVectorV1 = decode_copy(value, parent)?;
                if key != vector_key(workspace, generation.number, serial, row.representation_id)? {
                    return Err(integrity("router centroid copy key differs"));
                }
                // Full native tag, compact/full identity, canonical finite bits,
                // exact digest and declared L2 are checked without a live member.
                self.check_router_vector(workspace, manifest, &row, parent)?;
                Ok(())
            }
            CopyKind::Cohort => {
                let row: DirectoryRouterCohortV1 = decode_copy(value, parent)?;
                if key != cohort_key(workspace, generation.number, serial, &row.policy_domain)? {
                    return Err(integrity("router cohort copy key differs"));
                }
                self.check_router_cohort(workspace, manifest, &row, parent)?;
                Ok(())
            }
            CopyKind::Node => {
                let row: DirectoryRouterNodeV1 = decode_copy(value, parent)?;
                if key != node_key(workspace, generation.number, serial, row.representation_id)? {
                    return Err(integrity("router node copy key differs"));
                }
                self.check_router_node(workspace, manifest, &row, parent)?;
                Ok(())
            }
            CopyKind::Head => Err(integrity("router copy head namespace differs")),
        }
    }
    fn router_copy_generation<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        receipt: &DirectoryRouterReceiptV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let bytes = metered_json_len(&(generation, receipt), parent, ROW_BYTES * 2)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 8 + 8192)
            .map_err(budget_error)?;
        self.check_directory_router_generation_binding(
            snapshot, workspace, generation, receipt, parent,
        )
    }
    /// Independent retained fine acceptance survives deletion of its live rows.
    /// The contributor commitment/mean itself is reconstructed by deep verification.
    fn check_router_copy_fine_path<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        manifest: &DirectoryRouterManifestV1,
        row: &DirectoryRouterMemberV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        match &row.path {
            DirectoryRouterFinePathV1::Base { base } => {
                let accepted = self.accepted_prefix_base(
                    snapshot,
                    workspace,
                    manifest.raw.generation,
                    parent,
                )?;
                if self.prefix_segment_base_reference(snapshot, workspace, &accepted, parent)?
                    != *base
                {
                    return Err(integrity(
                        "router member fine base differs from retained native acceptance",
                    ));
                }
                let summary = accepted
                    .manifest
                    .cohorts
                    .iter()
                    .find(|c| c.policy_domain == row.policy_domain)
                    .ok_or_else(|| integrity("router member fine base cohort absent"))?;
                if summary.partition_digest != row.fine_partition_digest
                    || summary.nodes != row.contributors
                    || accepted.manifest.prefix.profile_digest != row.source_profile_digest
                    || accepted.manifest.prefix.vector_space_id != row.source_space_id
                {
                    return Err(integrity(
                        "router member fine base partition/count/space differs",
                    ));
                }
            }
            DirectoryRouterFinePathV1::Segment {
                ordinal,
                publication,
                receipt_digest,
                content_digest,
            } => {
                let accepted = self.accepted_prefix_segment_for_ordinal(
                    snapshot,
                    workspace,
                    manifest.raw.generation,
                    *ordinal,
                    parent,
                )?;
                let reference =
                    self.prefix_publication_ref(snapshot, accepted.delta.global_commit, parent)?;
                let bytes = metered_encode(&accepted.delta, parent, ROW_BYTES)?;
                parent
                    .charge(bytes.len() as u64 + 1, 64)
                    .map_err(budget_error)?;
                let digest =
                    contextdb_core::ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes());
                if reference != *publication
                    || digest != *receipt_digest
                    || accepted.delta.manifest.content_digest != *content_digest
                    || accepted.delta.manifest.base != manifest.coverage.base
                {
                    return Err(integrity("router member fine segment publication differs"));
                }
                let summary = accepted
                    .delta
                    .manifest
                    .cohorts
                    .iter()
                    .find(|c| c.policy_domain == row.policy_domain)
                    .ok_or_else(|| integrity("router member fine segment cohort absent"))?;
                if summary.partition_digest != row.fine_partition_digest
                    || summary.nodes != row.contributors
                    || accepted.delta.manifest.after.profile_digest != row.source_profile_digest
                    || accepted.delta.manifest.after.vector_space_id != row.source_space_id
                {
                    return Err(integrity(
                        "router member fine segment partition/count/space differs",
                    ));
                }
            }
        }
        Ok(())
    }
}
