//! Full-final-manifest router tags. Immutable acceptance grants no current permission.

pub(super) use super::super::segments::crypto::{metered_encode, metered_json_len};
use super::super::{ann_error, parameters, portable_epoch};
use super::types::*;
use crate::{
    NativeService, exhausted, integrity,
    raw_index::{budget_error, dense::DenseManifest},
};
use contextdb_core::{ContentDigest, Modality, RepresentationId, TimestampMicros, VectorSpaceId};
use contextdb_index::{
    AnnNodeV2, AnnPartitionManifestV2, VectorMetric, VectorSpace, ann_v2_partition_key,
};
use contextdb_recall::{QueryBudget, QueryLimit};
use contextdb_service::ServiceResult;
use serde::Serialize;
use std::io::{self, Write};

struct HashWriter<'a> {
    parent: &'a mut QueryBudget,
    hash: blake3::Hasher,
    bytes: usize,
    cap: usize,
    failure: Option<QueryLimit>,
    too_large: bool,
}
impl Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failure.is_some() || self.too_large {
            return Err(io::Error::other("router stream ended"));
        }
        let Some(total) = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= self.cap)
        else {
            self.too_large = true;
            return Err(io::Error::other("router stream exceeds its bound"));
        };
        if let Err(limit) = self
            .parent
            .charge(bytes.len() as u64 + 1, bytes.len() as u64)
        {
            self.failure = Some(limit);
            return Err(io::Error::other("router parent refused"));
        }
        self.hash.update(bytes);
        self.bytes = total;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failure.is_some() || self.too_large {
            return Err(io::Error::other("router stream ended"));
        }
        if let Err(limit) = self.parent.check() {
            self.failure = Some(limit);
            return Err(io::Error::other("router parent refused"));
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
        .charge(1, size_of::<HashWriter<'_>>() as u64 + 256)
        .map_err(budget_error)?;
    let cap = cap
        .checked_add(domain.len())
        .ok_or_else(|| exhausted("router hash bound overflow"))?;
    let mut writer = HashWriter {
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
        return Err(exhausted("router canonical stream exceeds its bound"));
    }
    result.map_err(|_| integrity("router canonical stream failed"))?;
    writer.parent.charge(1, 64).map_err(budget_error)?;
    Ok(ContentDigest::from_bytes(
        *writer.hash.finalize().as_bytes(),
    ))
}
pub(super) fn router_hash<T: Serialize>(
    domain: &[u8],
    value: &T,
    cap: usize,
    parent: &mut QueryBudget,
) -> ServiceResult<ContentDigest> {
    hashed(None, domain, value, cap, parent)
}
pub(super) fn representation_id(digest: ContentDigest) -> ServiceResult<RepresentationId> {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 15) | 128;
    bytes[8] = (bytes[8] & 63) | 128;
    RepresentationId::from_uuid(uuid::Uuid::from_bytes(bytes))
        .map_err(|_| integrity("router representation identity invalid"))
}
fn space_id(digest: ContentDigest) -> ServiceResult<VectorSpaceId> {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 15) | 128;
    bytes[8] = (bytes[8] & 63) | 128;
    VectorSpaceId::from_uuid(uuid::Uuid::from_bytes(bytes))
        .map_err(|_| integrity("router coarse space identity invalid"))
}

#[derive(Serialize)]
struct BuildHeader<'a> {
    database_id: &'a str,
    workspace: &'a str,
    revision: u16,
    serial: u64,
    previous: &'a Option<DirectoryRouterRefV1>,
    raw: &'a PrefixRawBindingV2,
    admitted_known_at: u64,
    admitted_global_commit: u64,
    coverage: &'a DirectoryRouterCoverageV1,
    covered: &'a DenseManifest,
    covered_dense: &'a AcceptedPublicationRef,
    ending: &'a CaptureBoundaryRefV2,
    coverage_count: u64,
    coverage_digest: ContentDigest,
    recipe: &'a DirectoryRouterRecipeV1,
    source_profile_digest: ContentDigest,
    source_space_id: VectorSpaceId,
    coarse_space_digest: ContentDigest,
    coarse_space_id: VectorSpaceId,
    representatives: u64,
    builder_revision: &'a str,
}
pub(super) fn router_member_identity(
    build: ContentDigest,
    row: &DirectoryRouterMemberV1,
    parent: &mut QueryBudget,
) -> ServiceResult<(ContentDigest, RepresentationId)> {
    let full = router_hash(
        IDENTITY_DOMAIN,
        &(
            build,
            &row.path,
            row.fine_partition_digest,
            &row.policy_domain,
            row.contributors,
            row.contributors_digest,
            &row.mode,
            row.source_profile_digest,
            row.source_space_id,
            row.coarse_space_id,
            row.vector_digest,
        ),
        ROW_BYTES,
        parent,
    )?;
    Ok((full, representation_id(full)?))
}
pub(super) fn router_input_identity(
    build: ContentDigest,
    input: &DirectoryRouterInputV1,
    coarse_space_id: VectorSpaceId,
    parent: &mut QueryBudget,
) -> ServiceResult<(ContentDigest, RepresentationId)> {
    let full = router_hash(
        IDENTITY_DOMAIN,
        &(
            build,
            &input.path,
            input.fine_partition_digest,
            &input.policy_domain,
            input.contributors,
            input.contributors_digest,
            &input.mode,
            input.source_profile_digest,
            input.source_space_id,
            coarse_space_id,
            input.vector_digest,
        ),
        ROW_BYTES,
        parent,
    )?;
    Ok((full, representation_id(full)?))
}

trait Tagged: Serialize + Clone {
    fn token_mut(&mut self) -> &mut String;
}
macro_rules! tagged{($($t:ty),+$(,)?)=>{$(impl Tagged for $t{fn token_mut(&mut self)->&mut String{&mut self.token}})+};}
tagged!(
    DirectoryRouterReceiptV1,
    RetainedDirectoryRouterLocatorV1,
    DirectoryRouterMemberV1,
    DirectoryRouterVectorV1,
    DirectoryRouterCohortV1,
    DirectoryRouterNodeV1
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
        Err(integrity("router workspace identity differs"))
    }
}

impl NativeService {
    pub(super) fn directory_router_space(
        &self,
        covered: &DenseManifest,
        recipe: &DirectoryRouterRecipeV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<(ContentDigest, VectorSpace)> {
        let bytes = metered_json_len(&(covered, recipe), parent, ROW_BYTES)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 8 + 4096)
            .map_err(budget_error)?;
        covered.validate(covered.through)?;
        recipe.validate()?;
        let digest = router_hash(
            SPACE_DOMAIN,
            &(
                &covered.profile,
                covered.profile_digest,
                covered.vector_space_id,
                covered.profile.dimensions,
                VectorMetric::Cosine,
                Modality::Text,
                recipe,
            ),
            ROW_BYTES,
            parent,
        )?;
        let id = space_id(digest)?;
        if id == covered.vector_space_id {
            return Err(integrity("router coarse/source compact space collision"));
        }
        let space = VectorSpace {
            id,
            dimensions: covered.profile.dimensions,
            metric: VectorMetric::Cosine,
            model_family: covered.profile.model_family.clone(),
            model_revision: covered.profile.model_revision.clone(),
            preprocessing_revision: digest.to_string(),
            modality: Modality::Text,
        };
        space.validate().map_err(ann_error)?;
        Ok((digest, space))
    }
    pub(super) fn directory_router_space_fields(
        &self,
        covered: &DenseManifest,
        recipe: &DirectoryRouterRecipeV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<(ContentDigest, VectorSpaceId)> {
        let (digest, space) = self.directory_router_space(covered, recipe, parent)?;
        Ok((digest, space.id))
    }
    pub(super) fn directory_router_build_digest(
        &self,
        workspace: &str,
        m: &DirectoryRouterManifestV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<ContentDigest> {
        workspace_identity(workspace)?;
        router_hash(
            BUILD_DOMAIN,
            &BuildHeader {
                database_id: &self.database_id,
                workspace,
                revision: m.revision,
                serial: m.serial,
                previous: &m.previous,
                raw: &m.raw,
                admitted_known_at: m.admitted_known_at,
                admitted_global_commit: m.admitted_global_commit,
                coverage: &m.coverage,
                covered: &m.covered,
                covered_dense: &m.covered_dense,
                ending: &m.ending,
                coverage_count: m.coverage_count,
                coverage_digest: m.coverage_digest,
                recipe: &m.recipe,
                source_profile_digest: m.source_profile_digest,
                source_space_id: m.source_space_id,
                coarse_space_digest: m.coarse_space_digest,
                coarse_space_id: m.coarse_space_id,
                representatives: m.representatives,
                builder_revision: &m.builder_revision,
            },
            ROW_BYTES,
            parent,
        )
    }
    fn check_router_space(
        &self,
        m: &DirectoryRouterManifestV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<VectorSpace> {
        let (digest, space) = self.directory_router_space(&m.covered, &m.recipe, parent)?;
        if digest != m.coarse_space_digest || space.id != m.coarse_space_id {
            return Err(integrity("router full coarse space differs"));
        }
        Ok(space)
    }
    fn router_token<T: Serialize>(
        &self,
        domain: &[u8],
        value: &T,
        parent: &mut QueryBudget,
    ) -> ServiceResult<String> {
        let token = hashed(Some(&self.token_key), domain, value, ROW_BYTES * 2, parent)?;
        parent.charge(1, 128).map_err(budget_error)?;
        Ok(token.to_string())
    }
    pub(crate) fn sign_directory_router_receipt(
        &self,
        row: &mut DirectoryRouterReceiptV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let copy = unsigned(row, parent)?;
        self.check_router_space(&row.manifest, parent)?;
        let token = self.router_token(RECEIPT_MAC, &copy, parent)?;
        install(row, token, |r| {
            r.validate()?;
            if r.database_id != self.database_id {
                return Err(integrity("router receipt database differs"));
            }
            Ok(())
        })
    }
    pub(crate) fn check_directory_router_receipt(
        &self,
        row: &DirectoryRouterReceiptV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let copy = unsigned(row, parent)?;
        row.validate()?;
        self.check_router_space(&row.manifest, parent)?;
        if row.database_id != self.database_id
            || row.token != self.router_token(RECEIPT_MAC, &copy, parent)?
        {
            return Err(integrity("router receipt owner authentication differs"));
        }
        Ok(())
    }
    pub(crate) fn sign_retained_directory_router_locator(
        &self,
        workspace: &str,
        row: &mut RetainedDirectoryRouterLocatorV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        workspace_identity(workspace)?;
        let copy = unsigned(row, parent)?;
        let token =
            self.router_token(LOCATOR_MAC, &(&self.database_id, workspace, copy), parent)?;
        install(row, token, |r| {
            r.validate()?;
            if r.workspace_digest != workspace {
                return Err(integrity("router locator workspace differs"));
            }
            Ok(())
        })
    }
    pub(crate) fn check_retained_directory_router_locator(
        &self,
        workspace: &str,
        row: &RetainedDirectoryRouterLocatorV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        workspace_identity(workspace)?;
        let copy = unsigned(row, parent)?;
        row.validate()?;
        if row.workspace_digest != workspace
            || row.token
                != self.router_token(LOCATOR_MAC, &(&self.database_id, workspace, copy), parent)?
        {
            return Err(integrity("router locator owner authentication differs"));
        }
        Ok(())
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "one final root commits all four distinct immutable row families under the caller budget"
    )]
    pub(super) fn directory_router_final_digest(
        &self,
        workspace: &str,
        m: &DirectoryRouterManifestV1,
        members: &[DirectoryRouterMemberV1],
        vectors: &[DirectoryRouterVectorV1],
        cohorts: &[DirectoryRouterCohortV1],
        nodes: &[DirectoryRouterNodeV1],
        parent: &mut QueryBudget,
    ) -> ServiceResult<ContentDigest> {
        parent.check().map_err(budget_error)?;
        workspace_identity(workspace)?;
        if members.is_empty()
            || members.len() > MAX_REPRESENTATIVES
            || members.len() as u64 != m.representatives
            || vectors.len() != members.len()
            || nodes.len() != members.len()
            || cohorts.len() != m.cohorts.len()
            || cohorts.len() > MAX_COHORTS
            || members
                .windows(2)
                .any(|p| p[0].representation_id >= p[1].representation_id)
            || vectors.iter().zip(members).any(|(v, r)| {
                v.representation_id != r.representation_id
                    || v.identity_digest != r.identity_digest
                    || v.policy_domain != r.policy_domain
                    || v.vector_digest != r.vector_digest
            })
            || nodes.iter().zip(members).any(|(n, r)| {
                n.representation_id != r.representation_id || n.policy_domain != r.policy_domain
            })
            || cohorts
                .iter()
                .zip(&m.cohorts)
                .any(|(r, c)| r.policy_domain != c.policy_domain)
            || members
                .iter()
                .any(|r| !r.token.is_empty() || nonzero(r.router_digest))
            || vectors
                .iter()
                .any(|r| !r.token.is_empty() || nonzero(r.router_digest))
            || cohorts
                .iter()
                .any(|r| !r.token.is_empty() || nonzero(r.router_digest))
            || nodes
                .iter()
                .any(|r| !r.token.is_empty() || nonzero(r.router_digest))
        {
            return Err(integrity(
                "router final digest requires complete canonical unsigned rows",
            ));
        }
        let bytes = metered_json_len(m, parent, ROW_BYTES)?;
        parent
            .charge(1, bytes as u64 * 16 + 4096)
            .map_err(budget_error)?;
        m.validate_header()?;
        let mut copy = m.clone();
        copy.content_digest = ContentDigest::from_bytes([0; 32]);
        let count = members.len() + vectors.len() + cohorts.len() + nodes.len() + 2;
        let cap = ROW_BYTES
            .checked_mul(count)
            .ok_or_else(|| exhausted("router final stream bound overflow"))?;
        router_hash(
            FINAL_DOMAIN,
            &(
                &self.database_id,
                workspace,
                copy,
                members,
                vectors,
                cohorts,
                nodes,
            ),
            cap,
            parent,
        )
    }
    fn router_row_token<T: Tagged>(
        &self,
        workspace: &str,
        m: &DirectoryRouterManifestV1,
        row: &T,
        domain: &[u8],
        parent: &mut QueryBudget,
    ) -> ServiceResult<String> {
        workspace_identity(workspace)?;
        metered_json_len(m, parent, ROW_BYTES)?;
        m.validate()?;
        let copy = unsigned(row, parent)?;
        self.router_token(domain, &(&self.database_id, workspace, m, copy), parent)
    }
    pub(crate) fn sign_router_member(
        &self,
        workspace: &str,
        m: &DirectoryRouterManifestV1,
        row: &mut DirectoryRouterMemberV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.router_row_token(workspace, m, row, MEMBER_MAC, parent)?;
        install(row, token, |r| r.validate(m))
    }
    pub(crate) fn check_router_member(
        &self,
        workspace: &str,
        m: &DirectoryRouterManifestV1,
        row: &DirectoryRouterMemberV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.router_row_token(workspace, m, row, MEMBER_MAC, parent)?;
        row.validate(m)?;
        let build = self.directory_router_build_digest(workspace, m, parent)?;
        let (full, id) = router_member_identity(build, row, parent)?;
        if row.token != token || row.identity_digest != full || row.representation_id != id {
            return Err(integrity("router member full identity or tag differs"));
        }
        Ok(())
    }
    pub(crate) fn sign_router_vector(
        &self,
        workspace: &str,
        m: &DirectoryRouterManifestV1,
        row: &mut DirectoryRouterVectorV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.router_row_token(workspace, m, row, VECTOR_MAC, parent)?;
        install(row, token, |r| r.validate(m))
    }
    pub(crate) fn check_router_vector(
        &self,
        workspace: &str,
        m: &DirectoryRouterManifestV1,
        row: &DirectoryRouterVectorV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<Vec<f32>> {
        let token = self.router_row_token(workspace, m, row, VECTOR_MAC, parent)?;
        row.validate(m)?;
        if row.token != token {
            return Err(integrity("router vector owner tag differs"));
        }
        parent
            .charge(
                row.values_bits.len() as u64 + 1,
                row.values_bits.len() as u64 * 4 + 256,
            )
            .map_err(budget_error)?;
        let mut values = Vec::with_capacity(row.values_bits.len());
        let mut hash = blake3::Hasher::new();
        let mut norm = 0_f64;
        for bits in &row.values_bits {
            parent.charge(1, 4).map_err(budget_error)?;
            let value = f32::from_bits(*bits);
            if !value.is_finite() || *bits == 0x8000_0000 {
                return Err(integrity(
                    "router centroid values are nonfinite or noncanonical",
                ));
            }
            norm += f64::from(value).powi(2);
            hash.update(&value.to_le_bytes());
            values.push(value);
        }
        if (norm - 1.0).abs() > 0.001
            || ContentDigest::from_bytes(*hash.finalize().as_bytes()) != row.vector_digest
        {
            return Err(integrity("router centroid digest or L2 differs"));
        }
        Ok(values)
    }
    pub(crate) fn sign_router_cohort(
        &self,
        workspace: &str,
        m: &DirectoryRouterManifestV1,
        row: &mut DirectoryRouterCohortV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.router_row_token(workspace, m, row, COHORT_MAC, parent)?;
        install(row, token, |r| r.validate(m))
    }
    /// Authenticate policy control and opaque partition bytes without ANN decoding.
    pub(crate) fn check_router_cohort_control(
        &self,
        workspace: &str,
        m: &DirectoryRouterManifestV1,
        row: &DirectoryRouterCohortV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.router_row_token(workspace, m, row, COHORT_MAC, parent)?;
        row.validate(m)?;
        if row.token != token {
            return Err(integrity("router cohort owner tag differs"));
        }
        parent
            .charge(
                row.partition.len() as u64 + 1,
                row.partition.len() as u64 * 5 + 4096,
            )
            .map_err(budget_error)?;
        let summary = m
            .cohorts
            .iter()
            .find(|c| c.policy_domain == row.policy_domain)
            .ok_or_else(|| integrity("router cohort summary absent"))?;
        if router_hash(b"", &row.policies, ROW_BYTES, parent)?.to_string() != row.policy_domain
            || ContentDigest::from_bytes(*blake3::hash(&row.partition).as_bytes())
                != summary.partition_digest
        {
            return Err(integrity("router cohort policy/partition control differs"));
        }
        Ok(())
    }

    pub(crate) fn check_router_cohort(
        &self,
        workspace: &str,
        m: &DirectoryRouterManifestV1,
        row: &DirectoryRouterCohortV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<AnnPartitionManifestV2> {
        self.check_router_cohort_control(workspace, m, row, parent)?;
        let partition = AnnPartitionManifestV2::decode_json(&row.partition).map_err(ann_error)?;
        let (index, summary) = m
            .cohorts
            .iter()
            .enumerate()
            .find(|(_, c)| c.policy_domain == row.policy_domain)
            .ok_or_else(|| integrity("router cohort summary absent"))?;
        let domain = *blake3::Hash::from_hex(&row.policy_domain)
            .map_err(ann_error)?
            .as_bytes();
        if partition.encode_json().map_err(ann_error)? != row.partition
            || partition.generation != m.raw.generation
            || partition.policy_digest != domain
            || partition.vector_space_id != m.coarse_space_id
            || partition.membership_epoch != portable_epoch(m.raw.authorization_epoch)?
            || partition.global_leaf_index != index as u64
            || partition.node_count != summary.nodes
            || partition.max_level > parameters().max_level
            || partition.valid_for_all_from != TimestampMicros(i64::MIN)
            || partition.valid_for_all_until.is_some()
        {
            return Err(integrity("router cohort policy/space/topology differs"));
        }
        Ok(partition)
    }
    pub(crate) fn sign_router_node(
        &self,
        workspace: &str,
        m: &DirectoryRouterManifestV1,
        row: &mut DirectoryRouterNodeV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let token = self.router_row_token(workspace, m, row, NODE_MAC, parent)?;
        install(row, token, |r| r.validate(m))
    }
    pub(crate) fn check_router_node(
        &self,
        workspace: &str,
        m: &DirectoryRouterManifestV1,
        row: &DirectoryRouterNodeV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<AnnNodeV2> {
        let token = self.router_row_token(workspace, m, row, NODE_MAC, parent)?;
        row.validate(m)?;
        if row.token != token {
            return Err(integrity("router node owner tag differs"));
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
            .ok_or_else(|| integrity("router node cohort absent"))?;
        if node.representation_id != row.representation_id
            || node.generation != m.raw.generation
            || node.partition_key
                != ann_v2_partition_key(m.coarse_space_id, domain).map_err(ann_error)?
            || node.leaf_index >= summary.nodes
            || node.levels.len() > parameters().max_level as usize + 1
        {
            return Err(integrity("router node representation/partition differs"));
        }
        Ok(node)
    }
}
