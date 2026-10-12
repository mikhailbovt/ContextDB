//! Immutable owner tags. Accepted publication and current access remain separate.

use super::super::{ann_error, parameters, portable_epoch};
use super::types::*;
use crate::{NativeService, encode, exhausted, integrity, raw_index::budget_error};
use contextdb_core::{ContentDigest, TimestampMicros};
use contextdb_index::{AnnNodeV2, AnnPartitionManifestV2, ann_v2_partition_key};
use contextdb_recall::{QueryBudget, QueryLimit};
use contextdb_service::ServiceResult;
use serde::Serialize;
use std::io::{self, Write};

/// Streaming serialization charges the shared allowance before each hash write.
/// A size-only pass also bounds cloning/encoding before any owned buffer exists.
struct Meter<'a> {
    budget: &'a mut QueryBudget,
    hasher: Option<&'a mut blake3::Hasher>,
    bytes: usize,
    cap: usize,
    limit: Option<QueryLimit>,
    too_large: bool,
}

impl Write for Meter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.limit.is_some() || self.too_large {
            return Err(io::Error::other("segment allowance ended"));
        }
        let Some(total) = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= self.cap)
        else {
            self.too_large = true;
            return Err(io::Error::other("segment encoding exceeds its bound"));
        };
        if let Err(limit) = self
            .budget
            .charge(bytes.len() as u64 + 1, bytes.len() as u64)
        {
            self.limit = Some(limit);
            return Err(io::Error::other("segment parent allowance ended"));
        }
        if let Some(hasher) = &mut self.hasher {
            hasher.update(bytes);
        }
        self.bytes = total;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.limit.is_some() || self.too_large {
            return Err(io::Error::other("segment allowance ended"));
        }
        if let Err(limit) = self.budget.check() {
            self.limit = Some(limit);
            return Err(io::Error::other("segment parent allowance ended"));
        }
        Ok(())
    }
}

fn stream<T: Serialize>(value: &T, meter: &mut Meter<'_>) -> ServiceResult<()> {
    let result = serde_json::to_writer(&mut *meter, value);
    if let Some(limit) = meter.limit {
        return Err(budget_error(limit));
    }
    if meter.too_large {
        return Err(exhausted("segment canonical encoding exceeds its bound"));
    }
    result.map_err(|_| integrity("segment canonical encoding failed"))
}

pub(crate) fn metered_json_len<T: Serialize>(
    value: &T,
    budget: &mut QueryBudget,
    cap: usize,
) -> ServiceResult<usize> {
    let mut meter = Meter {
        budget,
        hasher: None,
        bytes: 0,
        cap,
        limit: None,
        too_large: false,
    };
    stream(value, &mut meter)?;
    Ok(meter.bytes)
}

pub(crate) fn metered_encode<T: Serialize>(
    value: &T,
    budget: &mut QueryBudget,
    cap: usize,
) -> ServiceResult<Vec<u8>> {
    let bytes = metered_json_len(value, budget, cap)?;
    // serde_json's growing Vec plus the final owned buffer are admitted first.
    budget
        .charge(bytes as u64 + 1, bytes as u64 * 3 + 256)
        .map_err(budget_error)?;
    let encoded = encode(value)?;
    if encoded.len() != bytes {
        return Err(integrity("segment canonical size changed"));
    }
    Ok(encoded)
}

fn hashed<T: Serialize>(
    key: Option<&[u8; 32]>,
    domain: &[u8],
    value: &T,
    cap: usize,
    budget: &mut QueryBudget,
) -> ServiceResult<ContentDigest> {
    budget
        .charge(1, size_of::<blake3::Hasher>() as u64 + 256)
        .map_err(budget_error)?;
    let mut hasher = match key {
        Some(key) => blake3::Hasher::new_keyed(key),
        None => blake3::Hasher::new(),
    };
    let mut meter = Meter {
        budget,
        hasher: Some(&mut hasher),
        bytes: 0,
        cap: cap.saturating_add(domain.len()),
        limit: None,
        too_large: false,
    };
    let result = meter.write_all(domain);
    if let Some(limit) = meter.limit {
        return Err(budget_error(limit));
    }
    result.map_err(|_| integrity("segment domain encoding failed"))?;
    stream(value, &mut meter)?;
    meter.budget.charge(1, 64).map_err(budget_error)?;
    Ok(ContentDigest::from_bytes(*hasher.finalize().as_bytes()))
}

trait Tagged: Serialize + Clone {
    fn token_mut(&mut self) -> &mut String;
}
macro_rules! tagged {
    ($($row:ty),+ $(,)?) => { $(impl Tagged for $row {
        fn token_mut(&mut self) -> &mut String { &mut self.token }
    })+ };
}
tagged!(
    DenseDeltaReceipt,
    DenseSegmentDirectoryReceipt,
    RetainedSegmentLocator,
    SegMember,
    SegCohort,
    SegNode
);

fn unsigned<T: Tagged>(row: &T, budget: &mut QueryBudget) -> ServiceResult<T> {
    let bytes = metered_json_len(row, budget, ROW_BYTES)?;
    // Includes nested policy-set/map nodes as well as strings and byte vectors.
    budget
        .charge(1, bytes as u64 * 16 + size_of::<T>() as u64 + 4096)
        .map_err(budget_error)?;
    let mut value = row.clone();
    value.token_mut().clear();
    Ok(value)
}

fn install<T: Tagged>(
    row: &mut T,
    token: String,
    validate: impl FnOnce(&T) -> ServiceResult<()>,
) -> ServiceResult<()> {
    let old = std::mem::replace(row.token_mut(), token);
    if let Err(error) = validate(row) {
        *row.token_mut() = old;
        return Err(error);
    }
    Ok(())
}

fn workspace_identity(workspace: &str) -> ServiceResult<()> {
    if !valid_hex(workspace) {
        return Err(integrity("segment workspace digest differs"));
    }
    Ok(())
}

impl NativeService {
    fn segment_token<T: Serialize>(
        &self,
        domain: &[u8],
        value: &T,
        budget: &mut QueryBudget,
    ) -> ServiceResult<String> {
        let digest = hashed(Some(&self.token_key), domain, value, ROW_BYTES * 2, budget)?;
        budget.charge(1, 128).map_err(budget_error)?;
        Ok(digest.to_string())
    }

    pub(crate) fn sign_delta_receipt(
        &self,
        row: &mut DenseDeltaReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let copy = unsigned(row, budget)?;
        let token = self.segment_token(DELTA_RECEIPT_MAC, &copy, budget)?;
        install(row, token, |r| {
            r.validate()?;
            if r.database_id != self.database_id {
                return Err(integrity("delta receipt database differs"));
            }
            Ok(())
        })
    }

    pub(crate) fn check_delta_receipt(
        &self,
        row: &DenseDeltaReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let copy = unsigned(row, budget)?;
        row.validate()?;
        if row.database_id != self.database_id
            || row.token != self.segment_token(DELTA_RECEIPT_MAC, &copy, budget)?
        {
            return Err(integrity("delta receipt owner authentication differs"));
        }
        Ok(())
    }

    pub(crate) fn finalize_segment_directory_head(
        &self,
        workspace: &str,
        head: &mut DenseSegmentDirectoryHead,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let value = self.segment_directory_digest(workspace, head, budget)?;
        let old = std::mem::replace(&mut head.content_digest, value);
        if let Err(error) = head.validate() {
            head.content_digest = old;
            return Err(error);
        }
        Ok(())
    }

    fn segment_directory_digest(
        &self,
        workspace: &str,
        head: &DenseSegmentDirectoryHead,
        budget: &mut QueryBudget,
    ) -> ServiceResult<ContentDigest> {
        workspace_identity(workspace)?;
        let bytes = metered_json_len(head, budget, ROW_BYTES)?;
        budget
            .charge(1, bytes as u64 * 3 + 256)
            .map_err(budget_error)?;
        let mut unsigned = head.clone();
        unsigned.content_digest = ContentDigest::from_bytes([0; 32]);
        hashed(
            None,
            DIRECTORY_HEAD_DOMAIN,
            &(&self.database_id, workspace, unsigned),
            ROW_BYTES * 2,
            budget,
        )
    }

    pub(crate) fn sign_segment_directory_receipt(
        &self,
        row: &mut DenseSegmentDirectoryReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let copy = unsigned(row, budget)?;
        let workspace = crate::digest_bytes(row.workspace_id.as_bytes());
        if row.head.content_digest
            != self.segment_directory_digest(&workspace, &row.head, budget)?
        {
            return Err(integrity("segment directory content digest differs"));
        }
        let token = self.segment_token(DIRECTORY_RECEIPT_MAC, &copy, budget)?;
        install(row, token, |r| {
            r.validate()?;
            if r.database_id != self.database_id {
                return Err(integrity("segment directory database differs"));
            }
            Ok(())
        })
    }

    pub(crate) fn check_segment_directory_receipt(
        &self,
        row: &DenseSegmentDirectoryReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let copy = unsigned(row, budget)?;
        row.validate()?;
        let workspace = crate::digest_bytes(row.workspace_id.as_bytes());
        if row.database_id != self.database_id
            || row.head.content_digest
                != self.segment_directory_digest(&workspace, &row.head, budget)?
            || row.token != self.segment_token(DIRECTORY_RECEIPT_MAC, &copy, budget)?
        {
            return Err(integrity("segment directory owner authentication differs"));
        }
        Ok(())
    }

    pub(crate) fn sign_retained_segment_locator(
        &self,
        workspace: &str,
        row: &mut RetainedSegmentLocator,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        workspace_identity(workspace)?;
        if row.workspace_digest != workspace {
            return Err(integrity("segment locator workspace differs"));
        }
        let copy = unsigned(row, budget)?;
        let token =
            self.segment_token(LOCATOR_MAC, &(&self.database_id, workspace, copy), budget)?;
        install(row, token, RetainedSegmentLocator::validate)
    }

    pub(crate) fn check_retained_segment_locator(
        &self,
        workspace: &str,
        row: &RetainedSegmentLocator,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        workspace_identity(workspace)?;
        let copy = unsigned(row, budget)?;
        row.validate()?;
        if row.workspace_digest != workspace
            || row.token
                != self.segment_token(LOCATOR_MAC, &(&self.database_id, workspace, copy), budget)?
        {
            return Err(integrity(
                "retained segment locator owner authentication differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn segment_final_digest(
        &self,
        workspace: &str,
        manifest: &DenseDeltaManifest,
        members: &[SegMember],
        cohorts: &[SegCohort],
        nodes: &[SegNode],
        budget: &mut QueryBudget,
    ) -> ServiceResult<ContentDigest> {
        workspace_identity(workspace)?;
        if members.len() > MAX_NODES as usize
            || nodes.len() != members.len()
            || cohorts.len() > MAX_COHORTS
            || members
                .iter()
                .any(|r| !r.token.is_empty() || r.segment_digest.as_bytes() != &[0; 32])
            || cohorts
                .iter()
                .any(|r| !r.token.is_empty() || r.segment_digest.as_bytes() != &[0; 32])
            || nodes
                .iter()
                .any(|r| !r.token.is_empty() || r.segment_digest.as_bytes() != &[0; 32])
        {
            return Err(integrity(
                "segment final digest requires unsigned bounded topology",
            ));
        }
        let bytes = metered_json_len(manifest, budget, ROW_BYTES)?;
        budget
            .charge(1, bytes as u64 * 3 + 256)
            .map_err(budget_error)?;
        let mut unsigned = manifest.clone();
        unsigned.content_digest = ContentDigest::from_bytes([0; 32]);
        let cap = ROW_BYTES * (members.len() + cohorts.len() + nodes.len() + 2);
        hashed(
            None,
            DELTA_FINAL_DOMAIN,
            &(
                &self.database_id,
                workspace,
                unsigned,
                members,
                cohorts,
                nodes,
            ),
            cap,
            budget,
        )
    }

    fn segment_row_token<T: Tagged>(
        &self,
        workspace: &str,
        manifest: &DenseDeltaManifest,
        row: &T,
        domain: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<String> {
        workspace_identity(workspace)?;
        if manifest.cohorts.len() > MAX_COHORTS {
            return Err(integrity("segment cohort inventory exceeds its bound"));
        }
        metered_json_len(manifest, budget, ROW_BYTES)?;
        manifest.validate()?;
        let copy = unsigned(row, budget)?;
        self.segment_token(
            domain,
            &(&self.database_id, workspace, manifest, copy),
            budget,
        )
    }

    pub(crate) fn sign_segment_member(
        &self,
        workspace: &str,
        manifest: &DenseDeltaManifest,
        row: &mut SegMember,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.segment_row_token(workspace, manifest, row, DELTA_MEMBER_MAC, budget)?;
        install(row, token, |r| r.validate(manifest))
    }

    pub(crate) fn check_segment_member(
        &self,
        workspace: &str,
        manifest: &DenseDeltaManifest,
        row: &SegMember,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.segment_row_token(workspace, manifest, row, DELTA_MEMBER_MAC, budget)?;
        row.validate(manifest)?;
        if row.token != token {
            return Err(integrity("segment member owner authentication differs"));
        }
        let full = hashed(
            None,
            b"",
            &(
                "native-span-ann-member/v1",
                &self.database_id,
                workspace,
                manifest.binding.generation,
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
            budget,
        )?;
        let mut id = [0; 16];
        id.copy_from_slice(&full.as_bytes()[..16]);
        id[6] = (id[6] & 15) | 128;
        id[8] = (id[8] & 63) | 128;
        if row.identity_digest != full || row.representation_id.as_uuid().as_bytes() != &id {
            return Err(integrity(
                "segment member owner authentication or full identity differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn sign_segment_cohort(
        &self,
        workspace: &str,
        manifest: &DenseDeltaManifest,
        row: &mut SegCohort,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.segment_row_token(workspace, manifest, row, DELTA_COHORT_MAC, budget)?;
        install(row, token, |r| r.validate(manifest))
    }

    pub(crate) fn check_segment_cohort(
        &self,
        workspace: &str,
        manifest: &DenseDeltaManifest,
        row: &SegCohort,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AnnPartitionManifestV2> {
        if row.token
            != self.segment_row_token(workspace, manifest, row, DELTA_COHORT_MAC, budget)?
        {
            return Err(integrity("segment cohort owner authentication differs"));
        }
        row.validate(manifest)?;
        budget
            .charge(1, row.partition.len() as u64 * 5 + 4096)
            .map_err(budget_error)?;
        let partition = AnnPartitionManifestV2::decode_json(&row.partition).map_err(ann_error)?;
        let (index, summary) = manifest
            .cohorts
            .iter()
            .enumerate()
            .find(|(_, c)| c.policy_domain == row.policy_domain)
            .ok_or_else(|| integrity("segment cohort summary absent"))?;
        let policy = *blake3::Hash::from_hex(&row.policy_domain)
            .map_err(ann_error)?
            .as_bytes();
        let policy_digest = hashed(None, b"", &row.policies, ROW_BYTES, budget)?.to_string();
        if policy_digest != row.policy_domain
            || ContentDigest::from_bytes(*blake3::hash(&row.partition).as_bytes())
                != summary.partition_digest
            || partition.encode_json().map_err(ann_error)? != row.partition
            || partition.generation != manifest.binding.generation
            || partition.policy_digest != policy
            || partition.vector_space_id != manifest.after.vector_space_id
            || partition.membership_epoch != portable_epoch(manifest.binding.authorization_epoch)?
            || partition.global_leaf_index != index as u64
            || partition.node_count != summary.nodes
            || partition.max_level > parameters().max_level
            || partition.valid_for_all_from != TimestampMicros(i64::MIN)
            || partition.valid_for_all_until.is_some()
        {
            return Err(integrity(
                "segment cohort native policy or immutable topology differs",
            ));
        }
        Ok(partition)
    }

    pub(crate) fn sign_segment_node(
        &self,
        workspace: &str,
        manifest: &DenseDeltaManifest,
        row: &mut SegNode,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.segment_row_token(workspace, manifest, row, DELTA_NODE_MAC, budget)?;
        install(row, token, |r| r.validate(manifest))
    }

    pub(crate) fn check_segment_node(
        &self,
        workspace: &str,
        manifest: &DenseDeltaManifest,
        row: &SegNode,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AnnNodeV2> {
        if row.token != self.segment_row_token(workspace, manifest, row, DELTA_NODE_MAC, budget)? {
            return Err(integrity("segment node owner authentication differs"));
        }
        row.validate(manifest)?;
        budget
            .charge(1, row.canonical_node.len() as u64 * 4 + 4096)
            .map_err(budget_error)?;
        let node = AnnNodeV2::decode_canonical(&row.canonical_node).map_err(ann_error)?;
        let domain = *blake3::Hash::from_hex(&row.policy_domain)
            .map_err(ann_error)?
            .as_bytes();
        if node.representation_id != row.representation_id
            || node.generation != manifest.binding.generation
            || node.partition_key
                != ann_v2_partition_key(manifest.after.vector_space_id, domain)
                    .map_err(ann_error)?
        {
            return Err(integrity(
                "segment node representation or partition differs",
            ));
        }
        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contextdb_recall::QueryCancellation;
    use contextdb_service::ErrorCode;
    use std::time::Duration;

    fn budget() -> QueryBudget {
        QueryBudget::new(
            100_000,
            4 * 1024 * 1024,
            Duration::from_secs(10),
            Default::default(),
        )
    }

    #[test]
    fn streamed_owner_tag_matches_canonical_keyed_bytes_and_domains_differ() {
        let key = [17; 32];
        let value = ("full database", "full workspace", 7_u64, vec![1_u64, 2, 3]);
        let bytes = encode(&value).expect("canonical fixture");
        let tag = hashed(Some(&key), DELTA_RECEIPT_MAC, &value, 4096, &mut budget())
            .expect("streamed owner tag");
        assert_eq!(
            tag.to_string(),
            crate::keyed_token(&key, DELTA_RECEIPT_MAC, &bytes)
        );
        assert_ne!(
            tag,
            hashed(
                Some(&key),
                DIRECTORY_RECEIPT_MAC,
                &value,
                4096,
                &mut budget()
            )
            .expect("independent receipt domain")
        );
        assert_eq!(
            metered_encode(&value, &mut budget(), 4096).expect("bounded encoding"),
            bytes
        );
    }

    #[test]
    fn refused_stream_keeps_first_parent_limit_and_never_hashes_later_bytes() {
        let cancellation = QueryCancellation::default();
        let mut parent = QueryBudget::new(100, 1, Duration::from_secs(10), cancellation.clone());
        let mut hasher = blake3::Hasher::new();
        let before = *hasher.finalize().as_bytes();
        let mut meter = Meter {
            budget: &mut parent,
            hasher: Some(&mut hasher),
            bytes: 0,
            cap: 100,
            limit: None,
            too_large: false,
        };
        meter
            .write_all(b"too much")
            .expect_err("shared byte refusal");
        assert_eq!(meter.limit, Some(QueryLimit::Bytes));
        cancellation.cancel();
        meter.write_all(b"x").expect_err("sticky first refusal");
        meter.flush().expect_err("no replacement allowance");
        assert_eq!(meter.limit, Some(QueryLimit::Bytes));
        assert_eq!(*hasher.finalize().as_bytes(), before);
    }

    #[test]
    fn sizing_cap_and_cancellation_refuse_before_an_owned_encoding() {
        assert_eq!(
            metered_encode(&vec![0_u64; 64], &mut budget(), 10)
                .expect_err("size bound")
                .code,
            ErrorCode::ResourceExhausted
        );
        let cancellation = QueryCancellation::default();
        let mut parent = QueryBudget::new(
            100_000,
            4 * 1024 * 1024,
            Duration::from_secs(10),
            cancellation.clone(),
        );
        cancellation.cancel();
        assert_eq!(
            metered_encode(&"unchanged source bytes", &mut parent, 4096)
                .expect_err("shared cancellation")
                .code,
            ErrorCode::BudgetExhausted
        );
    }
}
