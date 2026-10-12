//! V2 owner tags over full final manifests. Acceptance and current access are separate.

use super::super::{ann_error, parameters, portable_epoch};
use super::types::*;
use crate::{NativeService, exhausted, integrity, raw_index::budget_error};
use contextdb_core::{ContentDigest, TimestampMicros};
use contextdb_index::{AnnNodeV2, AnnPartitionManifestV2, ann_v2_partition_key};
use contextdb_recall::{QueryBudget, QueryLimit};
use contextdb_service::ServiceResult;
use serde::Serialize;
use std::io::{self, Write};

pub(crate) use super::super::segments::crypto::{metered_encode, metered_json_len};

struct DigestWriter<'a> {
    parent: &'a mut QueryBudget,
    hash: blake3::Hasher,
    bytes: usize,
    cap: usize,
    failure: Option<QueryLimit>,
    too_large: bool,
}
impl Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failure.is_some() || self.too_large {
            return Err(io::Error::other("prefix segment stream ended"));
        }
        let Some(total) = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= self.cap)
        else {
            self.too_large = true;
            return Err(io::Error::other("prefix segment stream exceeds its bound"));
        };
        if let Err(limit) = self
            .parent
            .charge(bytes.len() as u64 + 1, bytes.len() as u64)
        {
            self.failure = Some(limit);
            return Err(io::Error::other("prefix segment parent refused"));
        }
        self.hash.update(bytes);
        self.bytes = total;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failure.is_some() || self.too_large {
            return Err(io::Error::other("prefix segment stream ended"));
        }
        if let Err(limit) = self.parent.check() {
            self.failure = Some(limit);
            return Err(io::Error::other("prefix segment parent refused"));
        }
        Ok(())
    }
}
fn hashed<T: Serialize>(
    key: Option<&[u8; 32]>,
    domain: &[u8],
    value: &T,
    cap: usize,
    parent: &mut QueryBudget,
) -> ServiceResult<ContentDigest> {
    parent
        .charge(1, size_of::<DigestWriter<'_>>() as u64 + 256)
        .map_err(budget_error)?;
    let cap = cap
        .checked_add(domain.len())
        .ok_or_else(|| exhausted("prefix segment hash cap overflow"))?;
    let mut writer = DigestWriter {
        parent,
        hash: key.map_or_else(blake3::Hasher::new, blake3::Hasher::new_keyed),
        bytes: 0,
        cap,
        failure: None,
        too_large: false,
    };
    let result = writer
        .write_all(domain)
        .and_then(|()| serde_json::to_writer(&mut writer, value).map_err(io::Error::other));
    if let Some(limit) = writer.failure {
        return Err(budget_error(limit));
    }
    if writer.too_large {
        return Err(exhausted(
            "prefix segment canonical stream exceeds its bound",
        ));
    }
    result.map_err(|_| integrity("prefix segment canonical stream failed"))?;
    writer.parent.charge(1, 64).map_err(budget_error)?;
    Ok(ContentDigest::from_bytes(
        *writer.hash.finalize().as_bytes(),
    ))
}

trait Tagged: Serialize + Clone {
    fn token_mut(&mut self) -> &mut String;
}
macro_rules! tagged { ($($row:ty),+ $(,)?) => { $(impl Tagged for $row { fn token_mut(&mut self)->&mut String { &mut self.token } })+ }; }
tagged!(
    PrefixDeltaReceiptV2,
    PrefixSegmentDirectoryReceiptV2,
    RetainedPrefixSegmentLocatorV2,
    PrefixSegMemberV2,
    PrefixSegCohortV2,
    PrefixSegNodeV2
);

fn unsigned<T: Tagged>(row: &T, parent: &mut QueryBudget) -> ServiceResult<T> {
    let bytes = metered_json_len(row, parent, ROW_BYTES)?;
    parent
        .charge(1, bytes as u64 * 16 + size_of::<T>() as u64 + 4096)
        .map_err(budget_error)?;
    let mut copy = row.clone();
    copy.token_mut().clear();
    Ok(copy)
}
fn install<T: Tagged>(
    row: &mut T,
    token: String,
    validate: impl FnOnce(&T) -> ServiceResult<()>,
) -> ServiceResult<()> {
    let previous = std::mem::replace(row.token_mut(), token);
    if let Err(error) = validate(row) {
        *row.token_mut() = previous;
        return Err(error);
    }
    Ok(())
}
fn workspace_identity(workspace: &str) -> ServiceResult<()> {
    if valid_hex(workspace) {
        Ok(())
    } else {
        Err(integrity("prefix segment workspace identity differs"))
    }
}

impl NativeService {
    fn prefix_segment_token<T: Serialize>(
        &self,
        domain: &[u8],
        value: &T,
        parent: &mut QueryBudget,
    ) -> ServiceResult<String> {
        let tag = hashed(Some(&self.token_key), domain, value, ROW_BYTES * 2, parent)?;
        parent.charge(1, 128).map_err(budget_error)?;
        Ok(tag.to_string())
    }
    pub(crate) fn sign_prefix_delta_receipt(
        &self,
        row: &mut PrefixDeltaReceiptV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let copy = unsigned(row, parent)?;
        let token = self.prefix_segment_token(DELTA_RECEIPT_MAC, &copy, parent)?;
        install(row, token, |r| {
            r.validate()?;
            if r.database_id != self.database_id {
                return Err(integrity("prefix delta receipt database differs"));
            }
            Ok(())
        })
    }
    pub(crate) fn check_prefix_delta_receipt(
        &self,
        row: &PrefixDeltaReceiptV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let copy = unsigned(row, parent)?;
        row.validate()?;
        if row.database_id != self.database_id
            || row.token != self.prefix_segment_token(DELTA_RECEIPT_MAC, &copy, parent)?
        {
            return Err(integrity(
                "prefix delta receipt owner authentication differs",
            ));
        }
        Ok(())
    }
    pub(crate) fn prefix_segment_directory_digest(
        &self,
        workspace: &str,
        head: &PrefixSegmentDirectoryHeadV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<ContentDigest> {
        workspace_identity(workspace)?;
        let bytes = metered_json_len(head, parent, ROW_BYTES)?;
        parent
            .charge(1, bytes as u64 * 16 + 4096)
            .map_err(budget_error)?;
        let mut copy = head.clone();
        copy.content_digest = ContentDigest::from_bytes([0; 32]);
        hashed(
            None,
            DIRECTORY_HEAD_DOMAIN,
            &(&self.database_id, workspace, copy),
            ROW_BYTES * 2,
            parent,
        )
    }
    pub(crate) fn sign_prefix_segment_directory_receipt(
        &self,
        row: &mut PrefixSegmentDirectoryReceiptV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let copy = unsigned(row, parent)?;
        parent
            .charge(row.workspace_id.len() as u64 + 1, 128)
            .map_err(budget_error)?;
        let workspace = crate::digest_bytes(row.workspace_id.as_bytes());
        if row.head.content_digest
            != self.prefix_segment_directory_digest(&workspace, &row.head, parent)?
        {
            return Err(integrity("prefix segment directory final digest differs"));
        }
        let token = self.prefix_segment_token(DIRECTORY_RECEIPT_MAC, &copy, parent)?;
        install(row, token, |r| {
            r.validate()?;
            if r.database_id != self.database_id {
                return Err(integrity("prefix segment directory database differs"));
            }
            Ok(())
        })
    }
    pub(crate) fn check_prefix_segment_directory_receipt(
        &self,
        row: &PrefixSegmentDirectoryReceiptV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let copy = unsigned(row, parent)?;
        row.validate()?;
        parent
            .charge(row.workspace_id.len() as u64 + 1, 128)
            .map_err(budget_error)?;
        let workspace = crate::digest_bytes(row.workspace_id.as_bytes());
        if row.database_id != self.database_id
            || row.head.content_digest
                != self.prefix_segment_directory_digest(&workspace, &row.head, parent)?
            || row.token != self.prefix_segment_token(DIRECTORY_RECEIPT_MAC, &copy, parent)?
        {
            return Err(integrity(
                "prefix segment directory owner authentication differs",
            ));
        }
        Ok(())
    }
    pub(crate) fn sign_retained_prefix_segment_locator(
        &self,
        workspace: &str,
        row: &mut RetainedPrefixSegmentLocatorV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        workspace_identity(workspace)?;
        let copy = unsigned(row, parent)?;
        let token =
            self.prefix_segment_token(LOCATOR_MAC, &(&self.database_id, workspace, copy), parent)?;
        install(row, token, |r| {
            r.validate()?;
            if r.workspace_digest != workspace {
                return Err(integrity("prefix segment locator workspace differs"));
            }
            Ok(())
        })
    }
    pub(crate) fn check_retained_prefix_segment_locator(
        &self,
        workspace: &str,
        row: &RetainedPrefixSegmentLocatorV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        workspace_identity(workspace)?;
        let copy = unsigned(row, parent)?;
        row.validate()?;
        if row.workspace_digest != workspace
            || row.token
                != self.prefix_segment_token(
                    LOCATOR_MAC,
                    &(&self.database_id, workspace, copy),
                    parent,
                )?
        {
            return Err(integrity(
                "prefix segment locator owner authentication differs",
            ));
        }
        Ok(())
    }
    pub(crate) fn prefix_segment_final_digest(
        &self,
        workspace: &str,
        m: &PrefixDeltaManifestV2,
        members: &[PrefixSegMemberV2],
        cohorts: &[PrefixSegCohortV2],
        nodes: &[PrefixSegNodeV2],
        parent: &mut QueryBudget,
    ) -> ServiceResult<ContentDigest> {
        workspace_identity(workspace)?;
        parent.check().map_err(budget_error)?;
        if members.len() > MAX_NODES as usize
            || members.len() as u64 != m.nodes
            || nodes.len() != members.len()
            || cohorts.len() != m.cohorts.len()
            || cohorts.len() > MAX_COHORTS
            || members
                .windows(2)
                .any(|p| p[0].representation_id >= p[1].representation_id)
            || nodes.iter().zip(members).any(|(n, r)| {
                n.representation_id != r.representation_id || n.policy_domain != r.policy_domain
            })
            || cohorts
                .windows(2)
                .any(|p| p[0].policy_domain >= p[1].policy_domain)
            || cohorts
                .iter()
                .zip(&m.cohorts)
                .any(|(r, c)| r.policy_domain != c.policy_domain)
            || members.iter().any(|r| {
                r.segment_ordinal != m.ordinal
                    || !r.token.is_empty()
                    || r.segment_digest.as_bytes() != &[0; 32]
            })
            || cohorts.iter().any(|r| {
                r.segment_ordinal != m.ordinal
                    || !r.token.is_empty()
                    || r.segment_digest.as_bytes() != &[0; 32]
            })
            || nodes.iter().any(|r| {
                r.segment_ordinal != m.ordinal
                    || !r.token.is_empty()
                    || r.segment_digest.as_bytes() != &[0; 32]
            })
        {
            return Err(integrity(
                "prefix segment final digest requires unsigned complete topology",
            ));
        }
        let bytes = metered_json_len(m, parent, ROW_BYTES)?;
        parent
            .charge(1, bytes as u64 * 16 + 4096)
            .map_err(budget_error)?;
        m.validate_interval()?;
        let mut copy = m.clone();
        copy.content_digest = ContentDigest::from_bytes([0; 32]);
        let cap = ROW_BYTES
            .checked_mul(members.len() + cohorts.len() + nodes.len() + 2)
            .ok_or_else(|| exhausted("prefix segment final digest bound overflow"))?;
        hashed(
            None,
            DELTA_FINAL_DOMAIN,
            &(&self.database_id, workspace, copy, members, cohorts, nodes),
            cap,
            parent,
        )
    }
    fn prefix_segment_row_token<T: Tagged>(
        &self,
        workspace: &str,
        m: &PrefixDeltaManifestV2,
        row: &T,
        domain: &[u8],
        parent: &mut QueryBudget,
    ) -> ServiceResult<String> {
        workspace_identity(workspace)?;
        metered_json_len(m, parent, ROW_BYTES)?;
        m.validate()?;
        let copy = unsigned(row, parent)?;
        self.prefix_segment_token(domain, &(&self.database_id, workspace, m, copy), parent)
    }
    pub(crate) fn sign_prefix_segment_member(
        &self,
        workspace: &str,
        m: &PrefixDeltaManifestV2,
        row: &mut PrefixSegMemberV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.prefix_segment_row_token(workspace, m, row, DELTA_MEMBER_MAC, parent)?;
        install(row, token, |r| r.validate(m))
    }
    pub(crate) fn check_prefix_segment_member(
        &self,
        workspace: &str,
        m: &PrefixDeltaManifestV2,
        row: &PrefixSegMemberV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.prefix_segment_row_token(workspace, m, row, DELTA_MEMBER_MAC, parent)?;
        row.validate(m)?;
        if row.token != token {
            return Err(integrity(
                "prefix segment member owner authentication differs",
            ));
        }
        // Actual source-span identity is unchanged. The authority domain is v2.
        let full = hashed(
            None,
            b"",
            &(
                "native-span-ann-member/v1",
                &self.database_id,
                workspace,
                m.raw.generation,
                &row.source,
                row.event_digest,
                row.commit,
                row.ordinal,
                &row.span,
                &row.policy_domain,
                row.profile_digest,
                row.vector_digest,
            ),
            ROW_BYTES,
            parent,
        )?;
        let mut id = [0; 16];
        id.copy_from_slice(&full.as_bytes()[..16]);
        id[6] = (id[6] & 15) | 128;
        id[8] = (id[8] & 63) | 128;
        if row.identity_digest != full || row.representation_id.as_uuid().as_bytes() != &id {
            return Err(integrity(
                "prefix segment member full source identity differs",
            ));
        }
        Ok(())
    }
    pub(crate) fn sign_prefix_segment_cohort(
        &self,
        workspace: &str,
        m: &PrefixDeltaManifestV2,
        row: &mut PrefixSegCohortV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.prefix_segment_row_token(workspace, m, row, DELTA_COHORT_MAC, parent)?;
        install(row, token, |r| r.validate(m))
    }
    pub(crate) fn check_prefix_segment_cohort(
        &self,
        workspace: &str,
        m: &PrefixDeltaManifestV2,
        row: &PrefixSegCohortV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<AnnPartitionManifestV2> {
        let token = self.prefix_segment_row_token(workspace, m, row, DELTA_COHORT_MAC, parent)?;
        row.validate(m)?;
        if row.token != token {
            return Err(integrity(
                "prefix segment cohort owner authentication differs",
            ));
        }
        parent
            .charge(
                row.partition.len() as u64 + 1,
                row.partition.len() as u64 * 5 + 4096,
            )
            .map_err(budget_error)?;
        let partition = AnnPartitionManifestV2::decode_json(&row.partition).map_err(ann_error)?;
        let (index, summary) = m
            .cohorts
            .iter()
            .enumerate()
            .find(|(_, c)| c.policy_domain == row.policy_domain)
            .ok_or_else(|| integrity("prefix segment cohort summary absent"))?;
        let policy = *blake3::Hash::from_hex(&row.policy_domain)
            .map_err(ann_error)?
            .as_bytes();
        if hashed(None, b"", &row.policies, ROW_BYTES, parent)?.to_string() != row.policy_domain
            || ContentDigest::from_bytes(*blake3::hash(&row.partition).as_bytes())
                != summary.partition_digest
            || partition.encode_json().map_err(ann_error)? != row.partition
            || partition.generation != m.raw.generation
            || partition.policy_digest != policy
            || partition.vector_space_id != m.after.vector_space_id
            || partition.membership_epoch != portable_epoch(m.raw.authorization_epoch)?
            || partition.global_leaf_index != index as u64
            || partition.node_count != summary.nodes
            || partition.max_level > parameters().max_level
            || partition.valid_for_all_from != TimestampMicros(i64::MIN)
            || partition.valid_for_all_until.is_some()
        {
            return Err(integrity(
                "prefix segment cohort full policy or topology differs",
            ));
        }
        Ok(partition)
    }
    pub(crate) fn sign_prefix_segment_node(
        &self,
        workspace: &str,
        m: &PrefixDeltaManifestV2,
        row: &mut PrefixSegNodeV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.prefix_segment_row_token(workspace, m, row, DELTA_NODE_MAC, parent)?;
        install(row, token, |r| r.validate(m))
    }
    pub(crate) fn check_prefix_segment_node(
        &self,
        workspace: &str,
        m: &PrefixDeltaManifestV2,
        row: &PrefixSegNodeV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<AnnNodeV2> {
        let token = self.prefix_segment_row_token(workspace, m, row, DELTA_NODE_MAC, parent)?;
        row.validate(m)?;
        if row.token != token {
            return Err(integrity(
                "prefix segment node owner authentication differs",
            ));
        }
        parent
            .charge(
                row.canonical_node.len() as u64 + 1,
                row.canonical_node.len() as u64 * 4 + 4096,
            )
            .map_err(budget_error)?;
        let node = AnnNodeV2::decode_canonical(&row.canonical_node).map_err(ann_error)?;
        let domain = *blake3::Hash::from_hex(&row.policy_domain)
            .map_err(ann_error)?
            .as_bytes();
        let summary = m
            .cohorts
            .iter()
            .find(|c| c.policy_domain == row.policy_domain)
            .ok_or_else(|| integrity("prefix segment node cohort absent"))?;
        if node.representation_id != row.representation_id
            || node.generation != m.raw.generation
            || node.partition_key
                != ann_v2_partition_key(m.after.vector_space_id, domain).map_err(ann_error)?
            || node.leaf_index >= summary.nodes
            || node.levels.len() > parameters().max_level as usize + 1
        {
            return Err(integrity(
                "prefix segment node representation or partition differs",
            ));
        }
        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contextdb_recall::QueryCancellation;
    use std::time::Duration;

    #[test]
    fn streamed_v2_tag_matches_canonical_bytes_and_excludes_old_domains() {
        let key = [19; 32];
        let value = ("full native interval", 7_u64, [1_u64, 2, 3]);
        let mut parent = QueryBudget::new(
            100_000,
            1024 * 1024,
            Duration::from_secs(10),
            Default::default(),
        );
        let tag = hashed(Some(&key), DELTA_RECEIPT_MAC, &value, 4096, &mut parent).expect("tag");
        assert_eq!(
            tag.to_string(),
            crate::keyed_token(
                &key,
                DELTA_RECEIPT_MAC,
                &crate::encode(&value).expect("bytes")
            )
        );
        for domain in [
            super::super::super::segments::types::DELTA_RECEIPT_MAC,
            super::super::super::prefix_v2::types::RECEIPT_MAC,
            DIRECTORY_RECEIPT_MAC,
        ] {
            assert_ne!(
                tag,
                hashed(Some(&key), domain, &value, 4096, &mut parent).expect("distinct tag")
            );
        }
    }
    #[test]
    fn cancelled_or_tiny_parent_refuses_before_hash_allocation() {
        let cancel = QueryCancellation::default();
        cancel.cancel();
        let mut parent = QueryBudget::new(100_000, 1024 * 1024, Duration::from_secs(10), cancel);
        assert_eq!(
            hashed(None, DELTA_FINAL_DOMAIN, &"metadata", 4096, &mut parent)
                .expect_err("cancelled")
                .code,
            contextdb_service::ErrorCode::BudgetExhausted
        );
        let mut tiny = QueryBudget::new(100_000, 1, Duration::from_secs(10), Default::default());
        assert!(hashed(None, DELTA_FINAL_DOMAIN, &"metadata", 4096, &mut tiny).is_err());
    }
}
