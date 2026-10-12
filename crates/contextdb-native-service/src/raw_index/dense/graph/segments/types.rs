//! Bounded segment formats. Shape validation grants no MAC or source authority.

use std::fmt;

use contextdb_core::{ContentDigest, OriginalSourceSpan, RawSource, RepresentationId};
use contextdb_index::{
    ANN_PARTITION_BUILD_REVISION_V2, ANN_V2_MAX_NODE_BYTES, ANN_V2_MAX_PARTITION_MANIFEST_BYTES,
    RAW_ANALYZER,
};
use contextdb_service::{AccessPolicy, ServiceResult};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};

use super::super::{GraphCohortSummary, graph_prefix};
use crate::{
    integrity,
    raw_index::{
        bm25::Bm25Profile,
        dense::{DenseManifest, DenseProjectionReceipt},
    },
};

#[cfg(test)]
mod tests;

pub(crate) const FEATURE: &str = "continuous-raw-span-ann-segments-v1";
pub(crate) const OPERATION: &str = "raw_span_ann_segment";
pub(crate) const MAX_WORK: u32 = 128;
pub(crate) const MAX_NODES: u64 = 256;
pub(crate) const MAX_COHORTS: usize = 64;
pub(crate) const ROW_BYTES: usize = 128 * 1024;
/// Numeric response_bytes in StoredIdempotency may need four bytes per byte.
pub(crate) const MAX_PUBLICATION_BYTES: usize = (ROW_BYTES - 4096) / 4;
/// Caller allowance for the final key, formatter temporaries and Vec growth.
pub(crate) const KEY_BYTES: u64 = 1024;
const MAX_POLICIES: usize = 128;

pub(crate) const DELTA_FINAL_DOMAIN: &[u8] = b"contextdb.native-span-ann-delta-final.v1\0";
pub(crate) const DELTA_RECEIPT_MAC: &[u8] = b"contextdb.native-span-ann-delta-receipt.v1\0";
pub(crate) const DELTA_MEMBER_MAC: &[u8] = b"contextdb.native-span-ann-delta-member.v1\0";
pub(crate) const DELTA_COHORT_MAC: &[u8] = b"contextdb.native-span-ann-delta-cohort.v1\0";
pub(crate) const DELTA_NODE_MAC: &[u8] = b"contextdb.native-span-ann-delta-node.v1\0";
pub(crate) const DIRECTORY_HEAD_DOMAIN: &[u8] = b"contextdb.native-span-ann-directory-head.v1\0";
pub(crate) const DIRECTORY_RECEIPT_MAC: &[u8] = b"contextdb.native-span-ann-directory-receipt.v1\0";
pub(crate) const LOCATOR_MAC: &[u8] = b"contextdb.native-span-ann-segment-locator.v1\0";
pub(crate) const WORKSPACE_HEADS_MAC: &[u8] = b"contextdb.native-span-ann-workspace-heads.v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcceptedPublicationRef {
    pub(crate) global_commit: u64,
    pub(crate) event_digest: String,
    pub(crate) request_digest: String,
    pub(crate) response_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BaseRef {
    pub(crate) publication: AcceptedPublicationRef,
    pub(crate) receipt_digest: ContentDigest,
    pub(crate) graph_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SegmentRef {
    pub(crate) ordinal: u64,
    pub(crate) global_commit: u64,
    /// Final delta content digest; receipt_digest binds its complete signed bytes.
    pub(crate) manifest_digest: ContentDigest,
    pub(crate) receipt_digest: ContentDigest,
}

/// Exact predecessor/head reference; fields are owner checked, not caller grants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRef {
    pub(crate) count: u64,
    pub(crate) global_commit: u64,
    pub(crate) request_digest: String,
    pub(crate) response_digest: String,
    pub(crate) content_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeltaGenerationBinding {
    pub(crate) generation: u64,
    pub(crate) custody_version: u16,
    pub(crate) analyzer: String,
    pub(crate) bm25: Bm25Profile,
    pub(crate) authorization_epoch: u64,
    pub(crate) removal_through: Option<u64>,
    pub(crate) raw_through: u64,
    pub(crate) raw_sources: u64,
}

/// Immutable finite interval; its full profiles and counters remain historical.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenseDeltaManifest {
    pub(crate) revision: u16,
    pub(crate) binding: DeltaGenerationBinding,
    pub(crate) ordinal: u64,
    pub(crate) base: BaseRef,
    pub(crate) before: DenseManifest,
    pub(crate) after: DenseManifest,
    pub(crate) target_dense: AcceptedPublicationRef,
    pub(crate) interval_digest: ContentDigest,
    pub(crate) work_items: u32,
    pub(crate) nodes: u64,
    #[serde(deserialize_with = "bounded_cohorts")]
    pub(crate) cohorts: Vec<GraphCohortSummary>,
    pub(crate) builder_revision: String,
    pub(crate) content_digest: ContentDigest,
}

/// Native-issued delta acceptance. Structural validation does not verify its MAC.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenseDeltaReceipt {
    /// Native database identity.
    pub database_id: String,
    /// Workspace whose accepted dense interval was sealed.
    pub workspace_id: String,
    /// Full immutable interval and final topology commitment.
    pub manifest: DenseDeltaManifest,
    /// Actual native publication position.
    pub global_commit: u64,
    /// Owner authentication over this complete receipt.
    pub token: String,
}

/// Fixed-size append-only directory head; no cloned history of segment receipts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenseSegmentDirectoryHead {
    pub(crate) revision: u16,
    pub(crate) generation: u64,
    pub(crate) base: BaseRef,
    pub(crate) count: u64,
    pub(crate) latest: SegmentRef,
    pub(crate) covered: DenseManifest,
    pub(crate) previous: Option<DirectoryRef>,
    pub(crate) content_digest: ContentDigest,
}

/// Native-issued head acceptance, independently joined to its publication event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenseSegmentDirectoryReceipt {
    /// Native database identity.
    pub database_id: String,
    /// Workspace owning this accepted directory.
    pub workspace_id: String,
    /// Fixed-size head of the immutable segment sequence.
    pub head: DenseSegmentDirectoryHead,
    /// Actual native publication position of the latest append.
    pub global_commit: u64,
    /// Owner authentication over this complete receipt.
    pub token: String,
}

/// One accepted journal response, sealing both the new delta and directory head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenseSegmentPublication {
    /// Newly sealed immutable interval.
    pub delta: DenseDeltaReceipt,
    /// Directory accepted in the same native transaction.
    pub directory: DenseSegmentDirectoryReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedSegmentLocator {
    pub(crate) revision: u16,
    pub(crate) workspace_digest: String,
    pub(crate) generation: u64,
    pub(crate) ordinal: u64,
    pub(crate) publication: AcceptedPublicationRef,
    pub(crate) token: String,
}

/// The signer binds this digest to the exact workspace frame, not the new event hash.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SegmentHeadStamp {
    pub(crate) revision: u16,
    pub(crate) map_digest: ContentDigest,
    pub(crate) token: String,
}

/// Explicit retained retry target; native admission resolves all asserted refs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealRequest {
    /// Exact retained raw generation to advance.
    pub generation: u64,
    /// Expected accepted predecessor, absent for the first append.
    pub previous: Option<DirectoryRef>,
    /// Exact accepted complete dense prefix to seal.
    pub target: DenseProjectionReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SegMember {
    pub(crate) segment_ordinal: u64,
    pub(crate) representation_id: RepresentationId,
    pub(crate) identity_digest: ContentDigest,
    pub(crate) source: RawSource,
    pub(crate) event_digest: ContentDigest,
    pub(crate) commit: u64,
    pub(crate) ordinal: u32,
    pub(crate) span: OriginalSourceSpan,
    pub(crate) policy_domain: String,
    pub(crate) profile_digest: ContentDigest,
    pub(crate) vector_digest: ContentDigest,
    pub(crate) segment_digest: ContentDigest,
    pub(crate) token: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SegCohort {
    pub(crate) segment_ordinal: u64,
    pub(crate) policy_domain: String,
    #[serde(deserialize_with = "bounded_policies")]
    pub(crate) policies: Vec<AccessPolicy>,
    #[serde(deserialize_with = "bounded_partition")]
    pub(crate) partition: Vec<u8>,
    pub(crate) segment_digest: ContentDigest,
    pub(crate) token: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SegNode {
    pub(crate) segment_ordinal: u64,
    pub(crate) representation_id: RepresentationId,
    pub(crate) policy_domain: String,
    #[serde(deserialize_with = "bounded_node")]
    pub(crate) canonical_node: Vec<u8>,
    pub(crate) segment_digest: ContentDigest,
    pub(crate) token: String,
}

pub(crate) fn valid_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn nonzero(value: ContentDigest) -> bool {
    value.as_bytes() != &[0; 32]
}
fn valid_name(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 1024 && !value.contains('\0')
}
fn require_shape(condition: bool, name: &'static str) -> ServiceResult<()> {
    if condition {
        Ok(())
    } else {
        Err(integrity(name))
    }
}

impl AcceptedPublicationRef {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        require_shape(
            self.global_commit > 0
                && valid_hex(&self.event_digest)
                && valid_hex(&self.request_digest)
                && valid_hex(&self.response_digest),
            "segment accepted publication reference differs",
        )
    }
}
impl BaseRef {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.publication.validate()?;
        require_shape(
            nonzero(self.receipt_digest) && nonzero(self.graph_digest),
            "segment immutable base reference differs",
        )
    }
}
impl SegmentRef {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        require_shape(
            self.ordinal > 0
                && self.global_commit > 0
                && nonzero(self.manifest_digest)
                && nonzero(self.receipt_digest),
            "segment entry reference differs",
        )
    }
}
impl DirectoryRef {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        require_shape(
            self.count > 0
                && self.global_commit > 0
                && valid_hex(&self.request_digest)
                && valid_hex(&self.response_digest)
                && nonzero(self.content_digest),
            "segment directory reference differs",
        )
    }
}
impl DeltaGenerationBinding {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.bm25.validate()?;
        require_shape(
            self.generation > 0
                && self.custody_version == crate::custody::CUSTODY_VERSION
                && self.analyzer == RAW_ANALYZER
                && self.authorization_epoch.checked_add(1).is_some()
                && self.raw_sources <= self.raw_through
                && self
                    .removal_through
                    .is_none_or(|through| through <= self.raw_through),
            "segment raw generation binding differs",
        )
    }
}
impl DenseDeltaManifest {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.binding.validate()?;
        self.base.validate()?;
        self.target_dense.validate()?;
        self.before.validate(self.binding.raw_through)?;
        self.after.validate(self.binding.raw_through)?;
        let work_width = self.after.through.checked_sub(self.before.through);
        let sources = self.after.sources.checked_sub(self.before.sources);
        let embedded = self
            .after
            .embedded_sources
            .checked_sub(self.before.embedded_sources);
        let omitted = self
            .after
            .omitted_sources
            .checked_sub(self.before.omitted_sources);
        let spans = self.after.spans.checked_sub(self.before.spans);
        let sum = self
            .cohorts
            .iter()
            .try_fold(0_u64, |total, cohort| total.checked_add(cohort.nodes));
        require_shape(
            self.revision == 1
                && self.ordinal > 0
                && (1..=MAX_WORK).contains(&self.work_items)
                && work_width.is_some_and(|width| width > 0 && u64::from(self.work_items) <= width)
                && sources.is_some_and(|count| count <= u64::from(self.work_items))
                && embedded
                    .zip(omitted)
                    .is_some_and(|(a, b)| a.checked_add(b) == sources)
                && spans == Some(self.nodes)
                && self.nodes <= MAX_NODES
                && embedded.is_some_and(|count| {
                    self.nodes >= count
                        && count
                            .checked_mul(64)
                            .is_some_and(|bound| self.nodes <= bound)
                })
                && self.before.spans > 0
                && self.before.profile == self.after.profile
                && self.before.profile_digest == self.after.profile_digest
                && self.before.vector_space_id == self.after.vector_space_id
                && nonzero(self.before.commitment)
                && nonzero(self.after.commitment)
                && self.after.through <= self.binding.raw_through
                && self.after.sources <= self.binding.raw_sources
                && (self.after.through != self.binding.raw_through
                    || self.after.sources == self.binding.raw_sources)
                && self.target_dense.global_commit > self.base.publication.global_commit
                && self.cohorts.len() <= MAX_COHORTS
                && sum == Some(self.nodes)
                && self
                    .cohorts
                    .windows(2)
                    .all(|pair| pair[0].policy_domain < pair[1].policy_domain)
                && self.cohorts.iter().all(|cohort| {
                    valid_hex(&cohort.policy_domain)
                        && cohort.nodes > 0
                        && cohort.nodes <= MAX_NODES
                        && nonzero(cohort.partition_digest)
                })
                && self.builder_revision == ANN_PARTITION_BUILD_REVISION_V2
                && nonzero(self.interval_digest)
                && nonzero(self.content_digest),
            "segment immutable delta contract differs",
        )
    }
}
impl DenseDeltaReceipt {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.manifest.validate()?;
        require_shape(
            valid_name(&self.database_id)
                && valid_name(&self.workspace_id)
                && self.global_commit > self.manifest.target_dense.global_commit
                && valid_hex(&self.token),
            "segment delta receipt shape differs",
        )
    }
}
impl DenseSegmentDirectoryHead {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.base.validate()?;
        self.latest.validate()?;
        self.covered.validate(self.covered.through)?;
        if let Some(previous) = &self.previous {
            previous.validate()?;
        }
        let prior = match &self.previous {
            None => self.count == 1,
            Some(previous) => {
                previous.count.checked_add(1) == Some(self.count)
                    && previous.global_commit < self.latest.global_commit
            }
        };
        require_shape(
            self.revision == 1
                && self.generation > 0
                && self.count > 0
                && self.latest.ordinal == self.count
                && prior
                && self.covered.spans > 0
                && nonzero(self.covered.commitment)
                && self.latest.global_commit > self.base.publication.global_commit
                && nonzero(self.content_digest),
            "segment directory head contract differs",
        )
    }
}
impl DenseSegmentDirectoryReceipt {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.head.validate()?;
        require_shape(
            valid_name(&self.database_id)
                && valid_name(&self.workspace_id)
                && self.global_commit == self.head.latest.global_commit
                && valid_hex(&self.token),
            "segment directory receipt shape differs",
        )
    }
}
impl DenseSegmentPublication {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.delta.validate()?;
        self.directory.validate()?;
        let m = &self.delta.manifest;
        let h = &self.directory.head;
        let receipt_digest =
            ContentDigest::from_bytes(*blake3::hash(&crate::encode(&self.delta)?).as_bytes());
        require_shape(
            self.delta.database_id == self.directory.database_id
                && self.delta.workspace_id == self.directory.workspace_id
                && self.delta.global_commit == self.directory.global_commit
                && m.binding.generation == h.generation
                && m.ordinal == h.count
                && m.base == h.base
                && m.after == h.covered
                && h.latest.manifest_digest == m.content_digest
                && h.latest.receipt_digest == receipt_digest,
            "segment combined publication join differs",
        )
    }
}
impl RetainedSegmentLocator {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.publication.validate()?;
        require_shape(
            self.revision == 1
                && valid_hex(&self.workspace_digest)
                && self.generation > 0
                && self.ordinal > 0
                && valid_hex(&self.token),
            "retained segment locator shape differs",
        )
    }
}
impl SegmentHeadStamp {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        require_shape(
            self.revision == 1 && nonzero(self.map_digest) && valid_hex(&self.token),
            "workspace segment head stamp shape differs",
        )
    }
}
impl SealRequest {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        let target = &self.target;
        if let Some(previous) = &self.previous {
            previous.validate()?;
        }
        let target_manifest = DenseManifest {
            profile: target.profile.clone(),
            profile_digest: target.profile_digest,
            vector_space_id: target.profile.vector_space_id()?,
            through: target.through,
            sources: target.sources,
            embedded_sources: target.embedded_sources,
            spans: target.spans,
            omitted_sources: target.omitted_sources,
            commitment: target.commitment,
        };
        target_manifest.validate(target.raw_through)?;
        require_shape(
            self.generation > 0
                && self.generation == target.generation
                && self.previous.as_ref().is_none_or(|p| {
                    p.count.checked_add(1).is_some() && p.global_commit < target.global_commit
                })
                && target.caught_up == (target.through == target.raw_through)
                && target.through <= target.raw_through
                && target.sources <= target.raw_sources
                && target.raw_sources <= target.raw_through
                && (target.through != target.raw_through || target.sources == target.raw_sources)
                && target.global_commit > 0
                && target.authorization_epoch.checked_add(1).is_some()
                && valid_name(&target.database_id)
                && valid_name(&target.workspace_id)
                && nonzero(target.commitment)
                && valid_hex(&target.token),
            "segment seal request target differs",
        )
    }
}

impl SegMember {
    pub(crate) fn validate(&self, manifest: &DenseDeltaManifest) -> ServiceResult<()> {
        require_shape(
            self.segment_ordinal == manifest.ordinal
                && self.segment_digest == manifest.content_digest
                && self.commit > manifest.before.through
                && self.commit <= manifest.after.through
                && self.ordinal < 64
                && self.profile_digest == manifest.after.profile_digest
                && nonzero(self.identity_digest)
                && nonzero(self.event_digest)
                && nonzero(self.vector_digest)
                && valid_hex(&self.policy_domain)
                && valid_hex(&self.token)
                && manifest
                    .cohorts
                    .iter()
                    .any(|cohort| cohort.policy_domain == self.policy_domain)
                && self.span.event_id == self.source.event_id
                && Some(self.span.payload_digest) == self.source.payload_digest
                && nonzero(self.span.payload_digest)
                && nonzero(self.span.span_digest)
                && self.span.start < self.span.end
                && self
                    .source
                    .byte_length
                    .is_some_and(|length| self.span.end <= length)
                && self.source.independent_source
                && self.source.omission.is_none(),
            "segment member immutable source binding differs",
        )
    }
}
impl SegCohort {
    pub(crate) fn validate(&self, manifest: &DenseDeltaManifest) -> ServiceResult<()> {
        require_shape(
            self.segment_ordinal == manifest.ordinal
                && self.segment_digest == manifest.content_digest
                && valid_hex(&self.policy_domain)
                && valid_hex(&self.token)
                && !self.policies.is_empty()
                && self.policies.len() <= MAX_POLICIES
                && !self.partition.is_empty()
                && self.partition.len() <= ANN_V2_MAX_PARTITION_MANIFEST_BYTES
                && manifest
                    .cohorts
                    .iter()
                    .any(|cohort| cohort.policy_domain == self.policy_domain),
            "segment cohort immutable binding differs",
        )
    }
}
impl SegNode {
    pub(crate) fn validate(&self, manifest: &DenseDeltaManifest) -> ServiceResult<()> {
        require_shape(
            self.segment_ordinal == manifest.ordinal
                && self.segment_digest == manifest.content_digest
                && valid_hex(&self.policy_domain)
                && valid_hex(&self.token)
                && !self.canonical_node.is_empty()
                && self.canonical_node.len() <= ANN_V2_MAX_NODE_BYTES
                && manifest
                    .cohorts
                    .iter()
                    .any(|cohort| cohort.policy_domain == self.policy_domain),
            "segment node immutable binding differs",
        )
    }
}

fn bounded_vec<'de, D, T, const N: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T, const N: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Bounded<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {N} segment entries")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|count| count > N) {
                return Err(de::Error::custom("segment sequence exceeds its bound"));
            }
            let mut values = Vec::new();
            for _ in 0..N {
                let Some(value) = sequence.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                return Err(de::Error::custom("segment sequence exceeds its bound"));
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Bounded::<T, N>(std::marker::PhantomData))
}
fn bounded_cohorts<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<GraphCohortSummary>, D::Error> {
    bounded_vec::<D, GraphCohortSummary, MAX_COHORTS>(d)
}
fn bounded_policies<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<AccessPolicy>, D::Error> {
    bounded_vec::<D, AccessPolicy, MAX_POLICIES>(d)
}
fn bounded_partition<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bounded_vec::<D, u8, ANN_V2_MAX_PARTITION_MANIFEST_BYTES>(d)
}
fn bounded_node<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bounded_vec::<D, u8, ANN_V2_MAX_NODE_BYTES>(d)
}

fn key_identity(workspace: &str, generation: u64) -> ServiceResult<()> {
    require_shape(
        valid_hex(workspace) && generation > 0,
        "segment key identity differs",
    )
}
pub(crate) fn segment_prefix(
    workspace: &str,
    generation: u64,
    ordinal: u64,
) -> ServiceResult<Vec<u8>> {
    key_identity(workspace, generation)?;
    require_shape(ordinal > 0, "segment key ordinal differs")?;
    let mut key = graph_prefix(workspace, generation);
    key.extend_from_slice(format!("segment/{ordinal:016x}/").as_bytes());
    Ok(key)
}
pub(crate) fn delta_receipt_key(
    workspace: &str,
    generation: u64,
    ordinal: u64,
) -> ServiceResult<Vec<u8>> {
    let mut key = segment_prefix(workspace, generation, ordinal)?;
    key.extend_from_slice(b"receipt");
    Ok(key)
}
pub(crate) fn directory_head_key(workspace: &str, generation: u64) -> ServiceResult<Vec<u8>> {
    key_identity(workspace, generation)?;
    let mut key = graph_prefix(workspace, generation);
    key.extend_from_slice(b"segments/head");
    Ok(key)
}
pub(crate) fn segment_member_key(
    workspace: &str,
    generation: u64,
    ordinal: u64,
    id: RepresentationId,
) -> ServiceResult<Vec<u8>> {
    let mut key = segment_prefix(workspace, generation, ordinal)?;
    key.extend_from_slice(format!("member/{id}").as_bytes());
    Ok(key)
}
pub(crate) fn segment_cohort_key(
    workspace: &str,
    generation: u64,
    ordinal: u64,
    domain: &str,
) -> ServiceResult<Vec<u8>> {
    require_shape(valid_hex(domain), "segment policy-domain key differs")?;
    let mut key = segment_prefix(workspace, generation, ordinal)?;
    key.extend_from_slice(format!("cohort/{domain}").as_bytes());
    Ok(key)
}
pub(crate) fn segment_node_key(
    workspace: &str,
    generation: u64,
    ordinal: u64,
    id: RepresentationId,
) -> ServiceResult<Vec<u8>> {
    let mut key = segment_prefix(workspace, generation, ordinal)?;
    key.extend_from_slice(format!("node/{id}").as_bytes());
    Ok(key)
}
pub(crate) fn retained_locator_key(
    workspace: &str,
    generation: u64,
    ordinal: u64,
) -> ServiceResult<Vec<u8>> {
    key_identity(workspace, generation)?;
    require_shape(ordinal > 0, "retained segment locator ordinal differs")?;
    Ok(format!("ann-segment/v1/{workspace}/{generation:016x}/{ordinal:016x}").into_bytes())
}
