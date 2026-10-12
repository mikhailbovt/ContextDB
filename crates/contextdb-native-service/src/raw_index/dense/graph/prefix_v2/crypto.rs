//! Full immutable prefix tags. Accepted publication and current access are separate proofs.

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
    budget: &'a mut QueryBudget,
    hash: blake3::Hasher,
    bytes: usize,
    cap: usize,
    failure: Option<QueryLimit>,
    too_large: bool,
}
impl Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failure.is_some() || self.too_large {
            return Err(io::Error::other("prefix stream ended"));
        }
        let Some(total) = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= self.cap)
        else {
            self.too_large = true;
            return Err(io::Error::other("prefix stream exceeds its bound"));
        };
        if let Err(failure) = self
            .budget
            .charge(bytes.len() as u64 + 1, bytes.len() as u64)
        {
            self.failure = Some(failure);
            return Err(io::Error::other("prefix parent refused"));
        }
        self.hash.update(bytes);
        self.bytes = total;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failure.is_some() || self.too_large {
            return Err(io::Error::other("prefix stream ended"));
        }
        if let Err(failure) = self.budget.check() {
            self.failure = Some(failure);
            return Err(io::Error::other("prefix parent refused"));
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
    let mut writer = DigestWriter {
        budget: parent,
        hash: key.map_or_else(blake3::Hasher::new, blake3::Hasher::new_keyed),
        bytes: 0,
        cap: cap.saturating_add(domain.len()),
        failure: None,
        too_large: false,
    };
    let result = writer
        .write_all(domain)
        .and_then(|()| serde_json::to_writer(&mut writer, value).map_err(io::Error::other));
    if let Some(failure) = writer.failure {
        return Err(budget_error(failure));
    }
    if writer.too_large {
        return Err(exhausted("prefix canonical stream exceeds its bound"));
    }
    result.map_err(|_| integrity("prefix canonical stream failed"))?;
    writer.budget.charge(1, 64).map_err(budget_error)?;
    Ok(ContentDigest::from_bytes(
        *writer.hash.finalize().as_bytes(),
    ))
}

trait Tagged: Serialize + Clone {
    fn token_mut(&mut self) -> &mut String;
}
macro_rules! tagged {
    ($($row:ty),+ $(,)?) => { $(impl Tagged for $row { fn token_mut(&mut self) -> &mut String { &mut self.token } })+ };
}
tagged!(
    DensePrefixBaseReceiptV2,
    RetainedPrefixBaseLocatorV2,
    PrefixMemberV2,
    PrefixCohortV2,
    PrefixNodeV2
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
        Err(integrity("prefix workspace identity differs"))
    }
}

impl NativeService {
    fn prefix_token<T: Serialize>(
        &self,
        domain: &[u8],
        value: &T,
        parent: &mut QueryBudget,
    ) -> ServiceResult<String> {
        let tag = hashed(Some(&self.token_key), domain, value, ROW_BYTES * 2, parent)?;
        parent.charge(1, 128).map_err(budget_error)?;
        Ok(tag.to_string())
    }
    pub(crate) fn sign_prefix_base_receipt(
        &self,
        row: &mut DensePrefixBaseReceiptV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let copy = unsigned(row, parent)?;
        let token = self.prefix_token(RECEIPT_MAC, &copy, parent)?;
        install(row, token, |r| {
            r.validate()?;
            if r.database_id != self.database_id {
                return Err(integrity("prefix receipt database differs"));
            }
            Ok(())
        })
    }
    pub(crate) fn check_prefix_base_receipt(
        &self,
        row: &DensePrefixBaseReceiptV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let copy = unsigned(row, parent)?;
        row.validate()?;
        if row.database_id != self.database_id
            || row.token != self.prefix_token(RECEIPT_MAC, &copy, parent)?
        {
            return Err(integrity("prefix receipt owner authentication differs"));
        }
        Ok(())
    }
    pub(crate) fn sign_retained_prefix_base_locator(
        &self,
        workspace: &str,
        row: &mut RetainedPrefixBaseLocatorV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        workspace_identity(workspace)?;
        let copy = unsigned(row, parent)?;
        let token =
            self.prefix_token(LOCATOR_MAC, &(&self.database_id, workspace, copy), parent)?;
        install(row, token, |r| {
            r.validate()?;
            if r.workspace_digest != workspace {
                return Err(integrity("prefix locator workspace differs"));
            }
            Ok(())
        })
    }
    pub(crate) fn check_retained_prefix_base_locator(
        &self,
        workspace: &str,
        row: &RetainedPrefixBaseLocatorV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        workspace_identity(workspace)?;
        let copy = unsigned(row, parent)?;
        row.validate()?;
        if row.workspace_digest != workspace
            || row.token
                != self.prefix_token(LOCATOR_MAC, &(&self.database_id, workspace, copy), parent)?
        {
            return Err(integrity("prefix locator owner authentication differs"));
        }
        Ok(())
    }
    pub(crate) fn prefix_final_digest(
        &self,
        workspace: &str,
        manifest: &DensePrefixBaseManifestV2,
        members: &[PrefixMemberV2],
        cohorts: &[PrefixCohortV2],
        nodes: &[PrefixNodeV2],
        parent: &mut QueryBudget,
    ) -> ServiceResult<ContentDigest> {
        workspace_identity(workspace)?;
        if members.is_empty()
            || members.len() > MAX_NODES as usize
            || nodes.len() != members.len()
            || members.len() as u64 != manifest.nodes
            || cohorts.len() != manifest.cohorts.len()
            || cohorts.len() > MAX_COHORTS
            || members
                .iter()
                .any(|r| !r.token.is_empty() || r.prefix_digest.as_bytes() != &[0; 32])
            || cohorts
                .iter()
                .any(|r| !r.token.is_empty() || r.prefix_digest.as_bytes() != &[0; 32])
            || nodes
                .iter()
                .any(|r| !r.token.is_empty() || r.prefix_digest.as_bytes() != &[0; 32])
        {
            return Err(integrity(
                "prefix final digest requires unsigned complete topology",
            ));
        }
        let bytes = metered_json_len(manifest, parent, ROW_BYTES)?;
        parent
            .charge(1, bytes as u64 * 16 + 4096)
            .map_err(budget_error)?;
        let mut copy = manifest.clone();
        copy.content_digest = ContentDigest::from_bytes([0; 32]);
        let cap = ROW_BYTES
            .checked_mul(members.len() + cohorts.len() + nodes.len() + 2)
            .ok_or_else(|| exhausted("prefix final digest bound overflow"))?;
        hashed(
            None,
            FINAL_DOMAIN,
            &(&self.database_id, workspace, copy, members, cohorts, nodes),
            cap,
            parent,
        )
    }
    fn prefix_row_token<T: Tagged>(
        &self,
        workspace: &str,
        manifest: &DensePrefixBaseManifestV2,
        row: &T,
        domain: &[u8],
        parent: &mut QueryBudget,
    ) -> ServiceResult<String> {
        workspace_identity(workspace)?;
        metered_json_len(manifest, parent, ROW_BYTES)?;
        manifest.validate()?;
        let copy = unsigned(row, parent)?;
        self.prefix_token(
            domain,
            &(&self.database_id, workspace, manifest, copy),
            parent,
        )
    }
    pub(crate) fn sign_prefix_member(
        &self,
        workspace: &str,
        m: &DensePrefixBaseManifestV2,
        row: &mut PrefixMemberV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.prefix_row_token(workspace, m, row, MEMBER_MAC, parent)?;
        install(row, token, |r| r.validate(m))
    }
    pub(crate) fn check_prefix_member(
        &self,
        workspace: &str,
        m: &DensePrefixBaseManifestV2,
        row: &PrefixMemberV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.prefix_row_token(workspace, m, row, MEMBER_MAC, parent)?;
        row.validate(m)?;
        if row.token != token {
            return Err(integrity("prefix member owner authentication differs"));
        }
        // This is the existing actual source-span identity, not a new alias domain.
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
            return Err(integrity("prefix member full source identity differs"));
        }
        Ok(())
    }
    pub(crate) fn sign_prefix_cohort(
        &self,
        workspace: &str,
        m: &DensePrefixBaseManifestV2,
        row: &mut PrefixCohortV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.prefix_row_token(workspace, m, row, COHORT_MAC, parent)?;
        install(row, token, |r| r.validate(m))
    }
    pub(crate) fn check_prefix_cohort(
        &self,
        workspace: &str,
        m: &DensePrefixBaseManifestV2,
        row: &PrefixCohortV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<AnnPartitionManifestV2> {
        let token = self.prefix_row_token(workspace, m, row, COHORT_MAC, parent)?;
        row.validate(m)?;
        if row.token != token {
            return Err(integrity("prefix cohort owner authentication differs"));
        }
        parent
            .charge(1, row.partition.len() as u64 * 5 + 4096)
            .map_err(budget_error)?;
        let partition = AnnPartitionManifestV2::decode_json(&row.partition).map_err(ann_error)?;
        let (index, summary) = m
            .cohorts
            .iter()
            .enumerate()
            .find(|(_, c)| c.policy_domain == row.policy_domain)
            .ok_or_else(|| integrity("prefix cohort summary absent"))?;
        let policy = *blake3::Hash::from_hex(&row.policy_domain)
            .map_err(ann_error)?
            .as_bytes();
        if hashed(None, b"", &row.policies, ROW_BYTES, parent)?.to_string() != row.policy_domain
            || ContentDigest::from_bytes(*blake3::hash(&row.partition).as_bytes())
                != summary.partition_digest
            || partition.encode_json().map_err(ann_error)? != row.partition
            || partition.generation != m.raw.generation
            || partition.policy_digest != policy
            || partition.vector_space_id != m.prefix.vector_space_id
            || partition.membership_epoch != portable_epoch(m.raw.authorization_epoch)?
            || partition.global_leaf_index != index as u64
            || partition.node_count != summary.nodes
            || partition.max_level > parameters().max_level
            || partition.valid_for_all_from != TimestampMicros(i64::MIN)
            || partition.valid_for_all_until.is_some()
        {
            return Err(integrity("prefix cohort full policy or topology differs"));
        }
        Ok(partition)
    }
    pub(crate) fn sign_prefix_node(
        &self,
        workspace: &str,
        m: &DensePrefixBaseManifestV2,
        row: &mut PrefixNodeV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.prefix_row_token(workspace, m, row, NODE_MAC, parent)?;
        install(row, token, |r| r.validate(m))
    }
    pub(crate) fn check_prefix_node(
        &self,
        workspace: &str,
        m: &DensePrefixBaseManifestV2,
        row: &PrefixNodeV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<AnnNodeV2> {
        let token = self.prefix_row_token(workspace, m, row, NODE_MAC, parent)?;
        row.validate(m)?;
        if row.token != token {
            return Err(integrity("prefix node owner authentication differs"));
        }
        parent
            .charge(1, row.canonical_node.len() as u64 * 4 + 4096)
            .map_err(budget_error)?;
        let node = AnnNodeV2::decode_canonical(&row.canonical_node).map_err(ann_error)?;
        let domain = *blake3::Hash::from_hex(&row.policy_domain)
            .map_err(ann_error)?
            .as_bytes();
        let summary = m
            .cohorts
            .iter()
            .find(|c| c.policy_domain == row.policy_domain)
            .ok_or_else(|| integrity("prefix node cohort summary absent"))?;
        if node.representation_id != row.representation_id
            || node.generation != m.raw.generation
            || node.partition_key
                != ann_v2_partition_key(m.prefix.vector_space_id, domain).map_err(ann_error)?
            || node.leaf_index >= summary.nodes
            || node.levels.len() > parameters().max_level as usize + 1
        {
            return Err(integrity("prefix node representation or partition differs"));
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
    fn streamed_v2_tag_is_exact_and_cannot_reuse_old_row_domain() {
        let key = [19; 32];
        let value = ("actual full binding", 7_u64, [1_u64, 2, 3]);
        let mut parent = QueryBudget::new(
            100_000,
            1024 * 1024,
            Duration::from_secs(10),
            Default::default(),
        );
        let tag = hashed(Some(&key), RECEIPT_MAC, &value, 4096, &mut parent).expect("streamed tag");
        assert_eq!(
            tag.to_string(),
            crate::keyed_token(&key, RECEIPT_MAC, &crate::encode(&value).expect("bytes"))
        );
        assert_ne!(
            tag,
            hashed(
                Some(&key),
                super::super::super::segments::types::DELTA_RECEIPT_MAC,
                &value,
                4096,
                &mut parent
            )
            .expect("distinct legacy tag")
        );
    }

    #[test]
    fn cancelled_parent_refuses_before_hash_or_buffer_admission() {
        let cancel = QueryCancellation::default();
        cancel.cancel();
        let mut parent = QueryBudget::new(100_000, 1024 * 1024, Duration::from_secs(10), cancel);
        assert_eq!(
            hashed(None, FINAL_DOMAIN, &"small metadata", 4096, &mut parent)
                .expect_err("cancelled")
                .code,
            contextdb_service::ErrorCode::BudgetExhausted
        );
        let mut tiny = QueryBudget::new(100_000, 1, Duration::from_secs(10), Default::default());
        assert!(hashed(None, FINAL_DOMAIN, &"small metadata", 4096, &mut tiny).is_err());
    }
}
