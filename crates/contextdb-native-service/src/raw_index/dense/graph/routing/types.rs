//! Native directory routing shapes. Structural validity grants no source or current-head authority.

use super::super::GraphCohortSummary;
pub(crate) use super::super::prefix_segments_v2::types::{
    AcceptedPublicationRef, CaptureBoundaryRefV2, PrefixRawBindingV2, PrefixSegmentBaseRefV2,
    PrefixSegmentDirectoryRefV2,
};
use crate::{integrity, raw_index::dense::DenseManifest};
use contextdb_core::{ContentDigest, RepresentationId, VectorSpaceId};
use contextdb_index::{
    ANN_PARTITION_BUILD_REVISION_V2, ANN_V2_MAX_NODE_BYTES, ANN_V2_MAX_PARTITION_MANIFEST_BYTES,
};
use contextdb_service::{AccessPolicy, ServiceResult};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};
use std::fmt;

pub(crate) const FEATURE: &str = "continuous-raw-span-ann-directory-router-v1";
pub(crate) const OPERATION: &str = "raw_span_ann_directory_router_v1";
pub(crate) const LOCATOR_OPERATION: &str = "raw_span_ann_directory_router_locator_v1";
pub(crate) const MAX_REPRESENTATIVES: usize = 4096;
pub(crate) const MAX_COHORTS: usize = 64;
pub(crate) const ROW_BYTES: usize = 128 * 1024;
pub(crate) const KEY_BYTES: u64 = 1024;
pub(crate) const MAX_PUBLICATION_BYTES: usize = (ROW_BYTES - 4096) / 4;
pub(crate) const RECIPE_REVISION: &str = "contextdb.native-directory-mean-unit-f64.v1";
pub(crate) const QUERY_TRANSFORM: &str = "identity-query-values.v1";
pub(crate) const COVERAGE_DOMAIN: &[u8] =
    b"contextdb.native-span-ann-directory-router-coverage.v1\0";
pub(crate) const SPACE_DOMAIN: &[u8] = b"contextdb.native-span-ann-directory-router-space.v1\0";
pub(crate) const CONTRIBUTORS_DOMAIN: &[u8] =
    b"contextdb.native-span-ann-directory-router-contributors.v1\0";
pub(crate) const BUILD_DOMAIN: &[u8] = b"contextdb.native-span-ann-directory-router-build.v1\0";
pub(crate) const IDENTITY_DOMAIN: &[u8] =
    b"contextdb.native-span-ann-directory-router-identity.v1\0";
pub(crate) const FINAL_DOMAIN: &[u8] = b"contextdb.native-span-ann-directory-router-final.v1\0";
pub(crate) const RECEIPT_MAC: &[u8] = b"contextdb.native-span-ann-directory-router-receipt.v1\0";
pub(crate) const MEMBER_MAC: &[u8] = b"contextdb.native-span-ann-directory-router-member.v1\0";
pub(crate) const VECTOR_MAC: &[u8] = b"contextdb.native-span-ann-directory-router-vector.v1\0";
pub(crate) const COHORT_MAC: &[u8] = b"contextdb.native-span-ann-directory-router-cohort.v1\0";
pub(crate) const NODE_MAC: &[u8] = b"contextdb.native-span-ann-directory-router-node.v1\0";
pub(crate) const LOCATOR_MAC: &[u8] = b"contextdb.native-span-ann-directory-router-locator.v1\0";
pub(crate) const WORKSPACE_HEADS_MAC: &[u8] =
    b"contextdb.native-span-ann-directory-router-workspace-heads.v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryRouterRecipeV1 {
    pub(crate) revision: String,
    pub(crate) query_transform: String,
}
impl DirectoryRouterRecipeV1 {
    pub(crate) fn fixed() -> Self {
        Self {
            revision: RECIPE_REVISION.into(),
            query_transform: QUERY_TRANSFORM.into(),
        }
    }
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        require(
            self.revision == RECIPE_REVISION && self.query_transform == QUERY_TRANSFORM,
            "directory router recipe differs",
        )
    }
}

/// Exact operator coverage target; caller fields are independently admitted by native proofs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRouterCoverageV1 {
    pub(crate) base: PrefixSegmentBaseRefV2,
    pub(crate) directory: Option<PrefixSegmentDirectoryRefV2>,
}
impl DirectoryRouterCoverageV1 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.base.validate()?;
        if let Some(directory) = &self.directory {
            directory.validate()?;
            require(
                directory.count.checked_add(1).is_some()
                    && directory.global_commit > self.base.publication.global_commit,
                "directory router coverage target differs",
            )?;
        }
        Ok(())
    }
    pub(crate) fn count(&self) -> ServiceResult<u64> {
        self.directory
            .as_ref()
            .map_or(Some(1), |d| d.count.checked_add(1))
            .ok_or_else(|| integrity("directory router coverage count overflow"))
    }
}

/// Cycle-free reference to one accepted immutable router revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRouterRefV1 {
    pub(crate) serial: u64,
    pub(crate) global_commit: u64,
    pub(crate) request_digest: String,
    pub(crate) response_digest: String,
    pub(crate) receipt_digest: ContentDigest,
    pub(crate) content_digest: ContentDigest,
}
impl DirectoryRouterRefV1 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        require(
            self.serial > 0
                && self.global_commit > 0
                && valid_hex(&self.request_digest)
                && valid_hex(&self.response_digest)
                && nonzero(self.receipt_digest)
                && nonzero(self.content_digest),
            "directory router reference differs",
        )
    }
}

/// Explicit maintenance request. Exact retries never reinstall historical roots.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRouterPublishRequestV1 {
    /// Retained real raw generation whose accepted fine paths are routed.
    pub generation: u64,
    /// Expected native predecessor, absent only for the first publication.
    pub previous: Option<DirectoryRouterRefV1>,
    /// Complete base and optional accepted directory target.
    pub coverage: DirectoryRouterCoverageV1,
}
impl DirectoryRouterPublishRequestV1 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.coverage.validate()?;
        if let Some(previous) = &self.previous {
            previous.validate()?;
        }
        require(
            self.generation > 0
                && self
                    .previous
                    .as_ref()
                    .is_none_or(|p| p.serial.checked_add(1).is_some()),
            "directory router publish request differs",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DirectoryRouterFinePathV1 {
    Base {
        base: PrefixSegmentBaseRefV2,
    },
    Segment {
        ordinal: u64,
        publication: AcceptedPublicationRef,
        receipt_digest: ContentDigest,
        content_digest: ContentDigest,
    },
}
impl DirectoryRouterFinePathV1 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        match self {
            Self::Base { base } => base.validate(),
            Self::Segment {
                ordinal,
                publication,
                receipt_digest,
                content_digest,
            } => {
                publication.validate()?;
                require(
                    *ordinal > 0 && nonzero(*receipt_digest) && nonzero(*content_digest),
                    "directory router fine segment differs",
                )
            }
        }
    }
    pub(crate) fn ordinal(&self) -> u64 {
        match self {
            Self::Base { .. } => 0,
            Self::Segment { ordinal, .. } => *ordinal,
        }
    }
    pub(crate) fn admitted_by(&self, coverage: &DirectoryRouterCoverageV1) -> bool {
        match self {
            Self::Base { base } => base == &coverage.base,
            Self::Segment {
                ordinal,
                publication,
                ..
            } => coverage.directory.as_ref().is_some_and(|d| {
                *ordinal > 0 && *ordinal <= d.count && publication.global_commit <= d.global_commit
            }),
        }
    }
    pub(crate) fn contributor_cap(&self) -> usize {
        match self {
            Self::Base { .. } => 4096,
            Self::Segment { .. } => 256,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DirectoryRouterCentroidModeV1 {
    Mean,
    FirstContributor {
        representation_id: RepresentationId,
        identity_digest: ContentDigest,
        vector_digest: ContentDigest,
    },
}
impl DirectoryRouterCentroidModeV1 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        match self {
            Self::Mean => Ok(()),
            Self::FirstContributor {
                identity_digest,
                vector_digest,
                ..
            } => require(
                nonzero(*identity_digest) && nonzero(*vector_digest),
                "directory router fallback identity differs",
            ),
        }
    }
}

/// Complete coverage and immutable derived routing topology; no serving activation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRouterManifestV1 {
    pub(crate) revision: u16,
    pub(crate) serial: u64,
    pub(crate) previous: Option<DirectoryRouterRefV1>,
    pub(crate) raw: PrefixRawBindingV2,
    pub(crate) admitted_known_at: u64,
    pub(crate) admitted_global_commit: u64,
    pub(crate) coverage: DirectoryRouterCoverageV1,
    pub(crate) covered: DenseManifest,
    pub(crate) covered_dense: AcceptedPublicationRef,
    pub(crate) ending: CaptureBoundaryRefV2,
    pub(crate) coverage_count: u64,
    pub(crate) coverage_digest: ContentDigest,
    pub(crate) recipe: DirectoryRouterRecipeV1,
    pub(crate) source_profile_digest: ContentDigest,
    pub(crate) source_space_id: VectorSpaceId,
    pub(crate) coarse_space_digest: ContentDigest,
    pub(crate) coarse_space_id: VectorSpaceId,
    pub(crate) representatives: u64,
    #[serde(deserialize_with = "bounded_cohorts")]
    pub(crate) cohorts: Vec<GraphCohortSummary>,
    pub(crate) builder_revision: String,
    pub(crate) content_digest: ContentDigest,
}
impl DirectoryRouterManifestV1 {
    pub(crate) fn validate_header(&self) -> ServiceResult<()> {
        self.raw.validate()?;
        self.coverage.validate()?;
        self.covered.validate(self.raw.through)?;
        self.covered_dense.validate()?;
        self.ending.validate()?;
        self.recipe.validate()?;
        if let Some(previous) = &self.previous {
            previous.validate()?;
        }
        let prior = match &self.previous {
            None => self.serial == 1,
            Some(p) => {
                p.serial.checked_add(1) == Some(self.serial)
                    && p.global_commit <= self.admitted_global_commit
            }
        };
        require(
            self.revision == 1
                && self.serial > 0
                && prior
                && self.admitted_known_at >= self.raw.through
                && self.admitted_global_commit >= self.admitted_known_at
                && self
                    .raw
                    .removal_through
                    .is_none_or(|at| at <= self.admitted_known_at)
                && self.coverage.base.publication.global_commit <= self.admitted_global_commit
                && self
                    .coverage
                    .directory
                    .as_ref()
                    .is_none_or(|d| d.global_commit <= self.admitted_global_commit)
                && self.covered_dense.global_commit <= self.admitted_global_commit
                && self.covered.sources <= self.raw.projected_sources
                && (self.covered.through != self.raw.through
                    || self.covered.sources == self.raw.projected_sources)
                && self.covered.spans > 0
                && nonzero(self.covered.commitment)
                && self.ending.work.workspace_commit <= self.covered.through
                && self.ending.global_commit <= self.covered_dense.global_commit
                && self.coverage_count == self.coverage.count()?
                && nonzero(self.coverage_digest)
                && self.source_profile_digest == self.covered.profile_digest
                && self.source_space_id == self.covered.vector_space_id
                && nonzero(self.coarse_space_digest)
                && self.coarse_space_id != self.source_space_id
                && compact_matches(
                    self.coarse_space_digest,
                    self.coarse_space_id.as_uuid().as_bytes(),
                )
                && (1..=MAX_REPRESENTATIVES as u64).contains(&self.representatives)
                && self.representatives <= self.covered.spans
                && self.builder_revision == ANN_PARTITION_BUILD_REVISION_V2,
            "directory router full header differs",
        )
    }
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.validate_header()?;
        let sum = self
            .cohorts
            .iter()
            .try_fold(0_u64, |n, c| n.checked_add(c.nodes));
        require(
            !self.cohorts.is_empty()
                && self.cohorts.len() <= MAX_COHORTS
                && sum == Some(self.representatives)
                && self
                    .cohorts
                    .windows(2)
                    .all(|p| p[0].policy_domain < p[1].policy_domain)
                && self.cohorts.iter().all(|c| {
                    valid_hex(&c.policy_domain)
                        && (1..=MAX_REPRESENTATIVES as u64).contains(&c.nodes)
                        && nonzero(c.partition_digest)
                })
                && nonzero(self.content_digest),
            "directory router final topology differs",
        )
    }
}

/// Native acceptance of one complete finite router. Quality and erasure remain separate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRouterReceiptV1 {
    /// Database that authenticated the router.
    pub database_id: String,
    /// Workspace owning its accepted fine paths.
    pub workspace_id: String,
    /// Full coverage, spaces, recipe and immutable topology commitment.
    pub manifest: DirectoryRouterManifestV1,
    /// Actual native publication position.
    pub global_commit: u64,
    /// Owner authentication over this complete receipt.
    pub token: String,
}
impl DirectoryRouterReceiptV1 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.manifest.validate()?;
        require(
            valid_name(&self.database_id)
                && valid_name(&self.workspace_id)
                && self.global_commit > self.manifest.admitted_global_commit
                && valid_hex(&self.token),
            "directory router receipt differs",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedDirectoryRouterLocatorV1 {
    pub(crate) revision: u16,
    pub(crate) workspace_digest: String,
    pub(crate) generation: u64,
    pub(crate) serial: u64,
    pub(crate) publication: AcceptedPublicationRef,
    pub(crate) token: String,
}
impl RetainedDirectoryRouterLocatorV1 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.publication.validate()?;
        require(
            self.revision == 1
                && valid_hex(&self.workspace_digest)
                && self.generation > 0
                && self.serial > 0
                && valid_hex(&self.token),
            "directory router retained locator differs",
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryRouterHeadStampV1 {
    pub(crate) revision: u16,
    pub(crate) map_digest: ContentDigest,
    pub(crate) token: String,
}
impl DirectoryRouterHeadStampV1 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        require(
            self.revision == 1 && nonzero(self.map_digest) && valid_hex(&self.token),
            "directory router head stamp differs",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryRouterMemberV1 {
    pub(crate) representation_id: RepresentationId,
    pub(crate) identity_digest: ContentDigest,
    pub(crate) path: DirectoryRouterFinePathV1,
    pub(crate) fine_partition_digest: ContentDigest,
    pub(crate) policy_domain: String,
    pub(crate) contributors: u64,
    pub(crate) contributors_digest: ContentDigest,
    pub(crate) mode: DirectoryRouterCentroidModeV1,
    pub(crate) source_profile_digest: ContentDigest,
    pub(crate) source_space_id: VectorSpaceId,
    pub(crate) coarse_space_id: VectorSpaceId,
    pub(crate) vector_digest: ContentDigest,
    pub(crate) router_digest: ContentDigest,
    pub(crate) token: String,
}
impl DirectoryRouterMemberV1 {
    pub(crate) fn validate(&self, m: &DirectoryRouterManifestV1) -> ServiceResult<()> {
        self.path.validate()?;
        self.mode.validate()?;
        require(
            self.router_digest == m.content_digest
                && self.path.admitted_by(&m.coverage)
                && (1..=self.path.contributor_cap() as u64).contains(&self.contributors)
                && valid_hex(&self.policy_domain)
                && valid_hex(&self.token)
                && nonzero(self.fine_partition_digest)
                && nonzero(self.contributors_digest)
                && nonzero(self.vector_digest)
                && nonzero(self.identity_digest)
                && compact_matches(
                    self.identity_digest,
                    self.representation_id.as_uuid().as_bytes(),
                )
                && self.source_profile_digest == m.source_profile_digest
                && self.source_space_id == m.source_space_id
                && self.coarse_space_id == m.coarse_space_id
                && m.cohorts
                    .iter()
                    .any(|c| c.policy_domain == self.policy_domain),
            "directory router member differs",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryRouterVectorV1 {
    pub(crate) representation_id: RepresentationId,
    pub(crate) identity_digest: ContentDigest,
    pub(crate) policy_domain: String,
    pub(crate) vector_digest: ContentDigest,
    #[serde(deserialize_with = "bounded_values")]
    pub(crate) values_bits: Vec<u32>,
    pub(crate) router_digest: ContentDigest,
    pub(crate) token: String,
}
impl DirectoryRouterVectorV1 {
    pub(crate) fn validate(&self, m: &DirectoryRouterManifestV1) -> ServiceResult<()> {
        require(
            self.router_digest == m.content_digest
                && nonzero(self.identity_digest)
                && nonzero(self.vector_digest)
                && compact_matches(
                    self.identity_digest,
                    self.representation_id.as_uuid().as_bytes(),
                )
                && valid_hex(&self.policy_domain)
                && valid_hex(&self.token)
                && self.values_bits.len() == m.covered.profile.dimensions as usize
                && m.cohorts
                    .iter()
                    .any(|c| c.policy_domain == self.policy_domain),
            "directory router vector shape differs",
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryRouterCohortV1 {
    pub(crate) policy_domain: String,
    #[serde(deserialize_with = "bounded_policies")]
    pub(crate) policies: Vec<AccessPolicy>,
    #[serde(deserialize_with = "bounded_partition")]
    pub(crate) partition: Vec<u8>,
    pub(crate) router_digest: ContentDigest,
    pub(crate) token: String,
}
impl DirectoryRouterCohortV1 {
    pub(crate) fn validate(&self, m: &DirectoryRouterManifestV1) -> ServiceResult<()> {
        require(
            self.router_digest == m.content_digest
                && valid_hex(&self.policy_domain)
                && valid_hex(&self.token)
                && !self.policies.is_empty()
                && self.policies.len() <= 128
                && !self.partition.is_empty()
                && self.partition.len() <= ANN_V2_MAX_PARTITION_MANIFEST_BYTES
                && m.cohorts
                    .iter()
                    .any(|c| c.policy_domain == self.policy_domain),
            "directory router cohort differs",
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryRouterNodeV1 {
    pub(crate) representation_id: RepresentationId,
    pub(crate) policy_domain: String,
    #[serde(deserialize_with = "bounded_node")]
    pub(crate) canonical_node: Vec<u8>,
    pub(crate) router_digest: ContentDigest,
    pub(crate) token: String,
}
impl DirectoryRouterNodeV1 {
    pub(crate) fn validate(&self, m: &DirectoryRouterManifestV1) -> ServiceResult<()> {
        require(
            self.router_digest == m.content_digest
                && valid_hex(&self.policy_domain)
                && valid_hex(&self.token)
                && !self.canonical_node.is_empty()
                && self.canonical_node.len() <= ANN_V2_MAX_NODE_BYTES
                && m.cohorts
                    .iter()
                    .any(|c| c.policy_domain == self.policy_domain),
            "directory router node differs",
        )
    }
}

/// Derived values only; the collector separately retains opaque complete source proofs.
pub(super) struct DirectoryRouterInputV1 {
    pub(super) path: DirectoryRouterFinePathV1,
    pub(super) fine_partition_digest: ContentDigest,
    pub(super) policies: Vec<AccessPolicy>,
    pub(super) policy_domain: String,
    pub(super) contributors: u64,
    pub(super) contributors_digest: ContentDigest,
    pub(super) values: Vec<f32>,
    pub(super) values_bits: Vec<u32>,
    pub(super) vector_digest: ContentDigest,
    pub(super) mode: DirectoryRouterCentroidModeV1,
    pub(super) source_profile_digest: ContentDigest,
    pub(super) source_space_id: VectorSpaceId,
}

pub(crate) fn valid_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn nonzero(d: ContentDigest) -> bool {
    d.as_bytes() != &[0; 32]
}
pub(super) fn compact_matches(d: ContentDigest, id: &[u8; 16]) -> bool {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&d.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 15) | 128;
    bytes[8] = (bytes[8] & 63) | 128;
    &bytes == id
}
fn valid_name(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 1024 && !s.contains('\0')
}
fn require(ok: bool, message: &'static str) -> ServiceResult<()> {
    if ok { Ok(()) } else { Err(integrity(message)) }
}
fn bounded_vec<'de, D: Deserializer<'de>, T: Deserialize<'de>, const CAP: usize>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    struct Bound<T, const CAP: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const CAP: usize> Visitor<'de> for Bound<T, CAP> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {CAP} directory router entries")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            if seq.size_hint().is_some_and(|n| n > CAP) {
                return Err(de::Error::custom(
                    "directory router sequence exceeds its bound",
                ));
            }
            let mut values = Vec::new();
            for _ in 0..CAP {
                let Some(value) = seq.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            if seq.next_element::<de::IgnoredAny>()?.is_some() {
                return Err(de::Error::custom(
                    "directory router sequence exceeds its bound",
                ));
            }
            Ok(values)
        }
    }
    d.deserialize_seq(Bound::<T, CAP>(std::marker::PhantomData))
}
fn bounded_cohorts<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<GraphCohortSummary>, D::Error> {
    bounded_vec::<D, _, MAX_COHORTS>(d)
}
fn bounded_policies<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<AccessPolicy>, D::Error> {
    bounded_vec::<D, _, 128>(d)
}
fn bounded_partition<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bounded_vec::<D, _, ANN_V2_MAX_PARTITION_MANIFEST_BYTES>(d)
}
fn bounded_node<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bounded_vec::<D, _, ANN_V2_MAX_NODE_BYTES>(d)
}
fn bounded_values<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u32>, D::Error> {
    bounded_vec::<D, _, 4096>(d)
}

fn key_identity(workspace: &str, generation: u64) -> ServiceResult<()> {
    require(
        valid_hex(workspace) && generation > 0,
        "directory router key identity differs",
    )
}
pub(crate) fn router_prefix(
    workspace: &str,
    generation: u64,
    serial: u64,
) -> ServiceResult<Vec<u8>> {
    key_identity(workspace, generation)?;
    require(serial > 0, "directory router key serial differs")?;
    Ok(format!(
        "{}dense/directory-router-v1/{serial:016x}/",
        crate::raw_index::generation_prefix(workspace, generation)
    )
    .into_bytes())
}
pub(crate) fn receipt_key(workspace: &str, generation: u64, serial: u64) -> ServiceResult<Vec<u8>> {
    let mut key = router_prefix(workspace, generation, serial)?;
    key.extend_from_slice(b"receipt");
    Ok(key)
}
pub(crate) fn head_key(workspace: &str, generation: u64) -> ServiceResult<Vec<u8>> {
    key_identity(workspace, generation)?;
    Ok(format!(
        "{}dense/directory-routers-v1/head",
        crate::raw_index::generation_prefix(workspace, generation)
    )
    .into_bytes())
}
pub(crate) fn member_key(
    workspace: &str,
    generation: u64,
    serial: u64,
    id: RepresentationId,
) -> ServiceResult<Vec<u8>> {
    let mut key = router_prefix(workspace, generation, serial)?;
    key.extend_from_slice(format!("member/{id}").as_bytes());
    Ok(key)
}
pub(crate) fn vector_key(
    workspace: &str,
    generation: u64,
    serial: u64,
    id: RepresentationId,
) -> ServiceResult<Vec<u8>> {
    let mut key = router_prefix(workspace, generation, serial)?;
    key.extend_from_slice(format!("vector/{id}").as_bytes());
    Ok(key)
}
pub(crate) fn cohort_key(
    workspace: &str,
    generation: u64,
    serial: u64,
    domain: &str,
) -> ServiceResult<Vec<u8>> {
    require(valid_hex(domain), "directory router cohort key differs")?;
    let mut key = router_prefix(workspace, generation, serial)?;
    key.extend_from_slice(format!("cohort/{domain}").as_bytes());
    Ok(key)
}
pub(crate) fn node_key(
    workspace: &str,
    generation: u64,
    serial: u64,
    id: RepresentationId,
) -> ServiceResult<Vec<u8>> {
    let mut key = router_prefix(workspace, generation, serial)?;
    key.extend_from_slice(format!("node/{id}").as_bytes());
    Ok(key)
}
pub(crate) fn retained_locator_key(
    workspace: &str,
    generation: u64,
    serial: u64,
) -> ServiceResult<Vec<u8>> {
    key_identity(workspace, generation)?;
    require(serial > 0, "directory router retained serial differs")?;
    Ok(format!("ann-directory-router/v1/{workspace}/{generation:016x}/{serial:016x}").into_bytes())
}
