//! Separate immutable prefix-segment formats. Shape checks grant no native authority.

use std::fmt;

use contextdb_core::{ContentDigest, OriginalSourceSpan, RawSource, RepresentationId};
use contextdb_index::{
    ANN_PARTITION_BUILD_REVISION_V2, ANN_V2_MAX_NODE_BYTES, ANN_V2_MAX_PARTITION_MANIFEST_BYTES,
};
use contextdb_service::{AccessPolicy, ServiceResult};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};

use super::super::GraphCohortSummary;
pub(crate) use super::super::{
    prefix_v2::types::{PrefixIntervalV2, PrefixRawBindingV2},
    segments::types::AcceptedPublicationRef,
};
use crate::{
    capture::CaptureWork,
    integrity,
    raw_index::dense::{DenseManifest, DenseProjectionReceipt},
};

pub(crate) const FEATURE: &str = "continuous-raw-span-ann-prefix-segments-v2";
pub(crate) const OPERATION: &str = "raw_span_ann_prefix_segment_v2";
pub(crate) const LOCATOR_OPERATION: &str = "raw_span_ann_prefix_segment_locator_v2";
pub(crate) const MAX_WORK: u32 = 128;
pub(crate) const MAX_NODES: u64 = 256;
pub(crate) const MAX_COHORTS: usize = 64;
pub(crate) const ROW_BYTES: usize = 128 * 1024;
/// Numeric bytes in the primary idempotency response can amplify fourfold.
pub(crate) const MAX_PUBLICATION_BYTES: usize = (ROW_BYTES - 4096) / 4;
pub(crate) const KEY_BYTES: u64 = 1024;
pub(crate) const INTERVAL_DOMAIN: &[u8] = b"contextdb.native-span-ann-prefix-segment-interval.v2\0";
pub(crate) const DELTA_FINAL_DOMAIN: &[u8] = b"contextdb.native-span-ann-prefix-delta-final.v2\0";
pub(crate) const DELTA_RECEIPT_MAC: &[u8] = b"contextdb.native-span-ann-prefix-delta-receipt.v2\0";
pub(crate) const DELTA_MEMBER_MAC: &[u8] = b"contextdb.native-span-ann-prefix-delta-member.v2\0";
pub(crate) const DELTA_COHORT_MAC: &[u8] = b"contextdb.native-span-ann-prefix-delta-cohort.v2\0";
pub(crate) const DELTA_NODE_MAC: &[u8] = b"contextdb.native-span-ann-prefix-delta-node.v2\0";
pub(crate) const DIRECTORY_HEAD_DOMAIN: &[u8] =
    b"contextdb.native-span-ann-prefix-directory-head.v2\0";
pub(crate) const DIRECTORY_RECEIPT_MAC: &[u8] =
    b"contextdb.native-span-ann-prefix-directory-receipt.v2\0";
pub(crate) const LOCATOR_MAC: &[u8] = b"contextdb.native-span-ann-prefix-segment-locator.v2\0";
pub(crate) const WORKSPACE_HEADS_MAC: &[u8] =
    b"contextdb.native-span-ann-prefix-segment-workspace-heads.v2\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrefixSegmentBaseRefV2 {
    pub(crate) publication: AcceptedPublicationRef,
    pub(crate) receipt_digest: ContentDigest,
    pub(crate) content_digest: ContentDigest,
}

/// A body-free accepted capture boundary, independently resolved by native proofs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureBoundaryRefV2 {
    pub(crate) work: CaptureWork,
    pub(crate) global_commit: u64,
    pub(crate) event_digest: String,
    pub(crate) receipt_digest: ContentDigest,
    pub(crate) control_digest: ContentDigest,
}

/// Current root reference omits its own event hash to avoid a frame-stamp cycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixSegmentDirectoryRefV2 {
    pub(crate) count: u64,
    pub(crate) global_commit: u64,
    pub(crate) request_digest: String,
    pub(crate) response_digest: String,
    pub(crate) content_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrefixSegmentRefV2 {
    pub(crate) ordinal: u64,
    pub(crate) global_commit: u64,
    pub(crate) manifest_digest: ContentDigest,
    pub(crate) receipt_digest: ContentDigest,
}

/// Complete finite interval over a genuine accepted prefix; no serving permission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixDeltaManifestV2 {
    pub(crate) revision: u16,
    pub(crate) raw: PrefixRawBindingV2,
    pub(crate) admitted_known_at: u64,
    pub(crate) admitted_global_commit: u64,
    pub(crate) ordinal: u64,
    pub(crate) base: PrefixSegmentBaseRefV2,
    pub(crate) before: DenseManifest,
    pub(crate) after: DenseManifest,
    pub(crate) before_dense: AcceptedPublicationRef,
    pub(crate) target_dense: AcceptedPublicationRef,
    pub(crate) start: CaptureBoundaryRefV2,
    pub(crate) end: CaptureBoundaryRefV2,
    pub(crate) interval: PrefixIntervalV2,
    pub(crate) nodes: u64,
    #[serde(deserialize_with = "bounded_cohorts")]
    pub(crate) cohorts: Vec<GraphCohortSummary>,
    pub(crate) builder_revision: String,
    pub(crate) content_digest: ContentDigest,
}

/// Native immutable delta receipt. Its tag does not establish current freshness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixDeltaReceiptV2 {
    /// Native database that authenticated the interval.
    pub database_id: String,
    /// Workspace owning these original source spans.
    pub workspace_id: String,
    /// Full raw, accepted dense, capture interval and final topology binding.
    pub manifest: PrefixDeltaManifestV2,
    /// Actual native publication position.
    pub global_commit: u64,
    /// Owner authentication over this complete receipt.
    pub token: String,
}

/// Fixed-size directory head; arbitrary history remains in immutable ordinal rows.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixSegmentDirectoryHeadV2 {
    pub(crate) revision: u16,
    pub(crate) generation: u64,
    pub(crate) base: PrefixSegmentBaseRefV2,
    pub(crate) count: u64,
    pub(crate) latest: PrefixSegmentRefV2,
    pub(crate) covered: DenseManifest,
    pub(crate) covered_dense: AcceptedPublicationRef,
    pub(crate) ending: CaptureBoundaryRefV2,
    pub(crate) previous: Option<PrefixSegmentDirectoryRefV2>,
    pub(crate) content_digest: ContentDigest,
}

/// Native directory acceptance, independently joined to its exact publication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixSegmentDirectoryReceiptV2 {
    /// Native database identity.
    pub database_id: String,
    /// Workspace whose directory was advanced.
    pub workspace_id: String,
    /// Fixed-size head accepted with the new interval.
    pub head: PrefixSegmentDirectoryHeadV2,
    /// Native publication position of that append.
    pub global_commit: u64,
    /// Owner authentication over this complete directory receipt.
    pub token: String,
}

/// One atomic accepted journal response, without copying prior interval history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixSegmentPublicationV2 {
    /// Newly sealed whole-source interval.
    pub delta: PrefixDeltaReceiptV2,
    /// Directory accepted in the same native frame.
    pub directory: PrefixSegmentDirectoryReceiptV2,
}

/// Explicit operator target; all caller references require native admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixSegmentSealRequestV2 {
    /// Actual retained raw generation owning the prefix base.
    pub generation: u64,
    /// Expected accepted predecessor; absent only for the first interval.
    pub previous: Option<PrefixSegmentDirectoryRefV2>,
    /// Exact accepted dense state through which to seal complete capture work.
    pub target: DenseProjectionReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedPrefixSegmentLocatorV2 {
    pub(crate) revision: u16,
    pub(crate) workspace_digest: String,
    pub(crate) generation: u64,
    pub(crate) ordinal: u64,
    pub(crate) publication: AcceptedPublicationRef,
    pub(crate) token: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrefixSegmentHeadStampV2 {
    pub(crate) revision: u16,
    pub(crate) map_digest: ContentDigest,
    pub(crate) token: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrefixSegMemberV2 {
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
pub(crate) struct PrefixSegCohortV2 {
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
pub(crate) struct PrefixSegNodeV2 {
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
fn nonzero(digest: ContentDigest) -> bool {
    digest.as_bytes() != &[0; 32]
}
fn valid_name(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 1024 && !value.contains('\0')
}
fn require(ok: bool, message: &'static str) -> ServiceResult<()> {
    if ok { Ok(()) } else { Err(integrity(message)) }
}

impl PrefixSegmentBaseRefV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.publication.validate()?;
        require(
            nonzero(self.receipt_digest) && nonzero(self.content_digest),
            "prefix segment base reference differs",
        )
    }
}
impl CaptureBoundaryRefV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        require(
            self.work.workspace_commit > 0
                && self.global_commit >= self.work.workspace_commit
                && nonzero(self.work.event_digest)
                && self.work.recovery_digest.is_none_or(nonzero)
                && valid_hex(&self.event_digest)
                && nonzero(self.receipt_digest)
                && nonzero(self.control_digest),
            "prefix segment capture boundary differs",
        )
    }
}
impl PrefixSegmentDirectoryRefV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        require(
            self.count > 0
                && self.global_commit > 0
                && valid_hex(&self.request_digest)
                && valid_hex(&self.response_digest)
                && nonzero(self.content_digest),
            "prefix segment directory reference differs",
        )
    }
}
impl PrefixSegmentRefV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        require(
            self.ordinal > 0
                && self.global_commit > 0
                && nonzero(self.manifest_digest)
                && nonzero(self.receipt_digest),
            "prefix segment ordinal reference differs",
        )
    }
}
impl PrefixDeltaManifestV2 {
    /// This check is also used before construction, while topology is unfinished.
    pub(crate) fn validate_interval(&self) -> ServiceResult<()> {
        self.raw.validate()?;
        self.base.validate()?;
        self.before_dense.validate()?;
        self.target_dense.validate()?;
        self.start.validate()?;
        self.end.validate()?;
        self.before.validate(self.raw.through)?;
        self.after.validate(self.raw.through)?;
        let sources = self.after.sources.checked_sub(self.before.sources);
        let embedded = self
            .after
            .embedded_sources
            .checked_sub(self.before.embedded_sources);
        let omitted = self
            .after
            .omitted_sources
            .checked_sub(self.before.omitted_sources);
        let width = self.after.through.checked_sub(self.before.through);
        require(
            self.revision == 2
                && self.ordinal > 0
                && self.admitted_known_at >= self.raw.through
                && self
                    .raw
                    .removal_through
                    .is_none_or(|at| at <= self.admitted_known_at)
                && self.admitted_global_commit >= self.admitted_known_at
                && self.base.publication.global_commit <= self.admitted_global_commit
                && self.target_dense.global_commit <= self.admitted_global_commit
                && self.before_dense.global_commit < self.target_dense.global_commit
                && self.base.publication.global_commit < self.target_dense.global_commit
                && (1..=MAX_WORK).contains(&self.interval.work_items)
                && width.is_some_and(|n| n > 0 && u64::from(self.interval.work_items) <= n)
                && sources.is_some_and(|n| n <= u64::from(self.interval.work_items))
                && embedded
                    .zip(omitted)
                    .is_some_and(|(a, b)| a.checked_add(b) == sources)
                && self.after.spans.checked_sub(self.before.spans) == Some(self.nodes)
                && self.nodes <= MAX_NODES
                && embedded.is_some_and(|n| {
                    self.nodes >= n && n.checked_mul(64).is_some_and(|cap| self.nodes <= cap)
                })
                && self.before.spans > 0
                && self.before.profile == self.after.profile
                && self.before.profile_digest == self.after.profile_digest
                && self.before.vector_space_id == self.after.vector_space_id
                && self.after.sources <= self.raw.projected_sources
                && (self.after.through != self.raw.through
                    || self.after.sources == self.raw.projected_sources)
                && self.start.work.workspace_commit <= self.before.through
                && self.end.work.workspace_commit > self.before.through
                && self.end.work.workspace_commit <= self.after.through
                && self.start.global_commit < self.end.global_commit
                && self.start.work.event_id != self.end.work.event_id
                && self.start.global_commit <= self.before_dense.global_commit
                && self.end.global_commit <= self.target_dense.global_commit
                && self.builder_revision == ANN_PARTITION_BUILD_REVISION_V2
                && nonzero(self.before.commitment)
                && nonzero(self.after.commitment)
                && nonzero(self.interval.digest),
            "prefix segment complete interval contract differs",
        )
    }
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.validate_interval()?;
        let sum = self
            .cohorts
            .iter()
            .try_fold(0_u64, |n, c| n.checked_add(c.nodes));
        require(
            self.cohorts.len() <= MAX_COHORTS
                && sum == Some(self.nodes)
                && self
                    .cohorts
                    .windows(2)
                    .all(|p| p[0].policy_domain < p[1].policy_domain)
                && self.cohorts.iter().all(|c| {
                    valid_hex(&c.policy_domain)
                        && (1..=MAX_NODES).contains(&c.nodes)
                        && nonzero(c.partition_digest)
                })
                && nonzero(self.content_digest),
            "prefix segment immutable topology differs",
        )
    }
}
impl PrefixDeltaReceiptV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.manifest.validate()?;
        require(
            valid_name(&self.database_id)
                && valid_name(&self.workspace_id)
                && self.global_commit > self.manifest.admitted_global_commit
                && valid_hex(&self.token),
            "prefix segment receipt shape differs",
        )
    }
}
impl PrefixSegmentDirectoryHeadV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.base.validate()?;
        self.latest.validate()?;
        self.covered.validate(self.covered.through)?;
        self.covered_dense.validate()?;
        self.ending.validate()?;
        if let Some(previous) = &self.previous {
            previous.validate()?;
        }
        let prior = match &self.previous {
            None => self.count == 1,
            Some(p) => {
                p.count.checked_add(1) == Some(self.count)
                    && p.global_commit < self.latest.global_commit
            }
        };
        require(
            self.revision == 2
                && self.generation > 0
                && self.count > 0
                && self.latest.ordinal == self.count
                && prior
                && self.covered.spans > 0
                && self.latest.global_commit > self.base.publication.global_commit
                && self.latest.global_commit > self.covered_dense.global_commit
                && self.ending.work.workspace_commit <= self.covered.through
                && self.ending.global_commit <= self.covered_dense.global_commit
                && nonzero(self.covered.commitment)
                && nonzero(self.content_digest),
            "prefix segment directory head differs",
        )
    }
}
impl PrefixSegmentDirectoryReceiptV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.head.validate()?;
        require(
            valid_name(&self.database_id)
                && valid_name(&self.workspace_id)
                && self.global_commit == self.head.latest.global_commit
                && valid_hex(&self.token),
            "prefix segment directory receipt differs",
        )
    }
}
impl PrefixSegmentPublicationV2 {
    /// Structural joins only; the receipt digest is joined under a supplied parent.
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.delta.validate()?;
        self.directory.validate()?;
        let m = &self.delta.manifest;
        let h = &self.directory.head;
        require(
            self.delta.database_id == self.directory.database_id
                && self.delta.workspace_id == self.directory.workspace_id
                && self.delta.global_commit == self.directory.global_commit
                && m.raw.generation == h.generation
                && m.ordinal == h.count
                && m.base == h.base
                && m.after == h.covered
                && m.target_dense == h.covered_dense
                && m.end == h.ending
                && h.latest.manifest_digest == m.content_digest,
            "prefix segment combined publication join differs",
        )
    }
}
impl PrefixSegmentSealRequestV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        let t = &self.target;
        if let Some(p) = &self.previous {
            p.validate()?;
        }
        crate::raw_index::dense::validate_profile(&t.profile)?;
        require(
            self.generation > 0
                && self.generation == t.generation
                && t.global_commit > 0
                && t.authorization_epoch.checked_add(1).is_some()
                && valid_name(&t.database_id)
                && valid_name(&t.workspace_id)
                && valid_hex(&t.token)
                && t.through > 0
                && t.through <= t.raw_through
                && t.sources <= t.raw_sources
                && t.raw_sources <= t.raw_through
                && t.sources <= t.through
                && t.embedded_sources.checked_add(t.omitted_sources) == Some(t.sources)
                && t.spans >= t.embedded_sources
                && t.embedded_sources
                    .checked_mul(64)
                    .is_some_and(|cap| t.spans <= cap)
                && t.caught_up == (t.through == t.raw_through)
                && (t.through != t.raw_through || t.sources == t.raw_sources)
                && t.profile_digest == t.profile.digest()?
                && nonzero(t.commitment)
                && self.previous.as_ref().is_none_or(|p| {
                    p.count.checked_add(1).is_some() && p.global_commit < t.global_commit
                }),
            "prefix segment seal request differs",
        )
    }
}
impl RetainedPrefixSegmentLocatorV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.publication.validate()?;
        require(
            self.revision == 2
                && valid_hex(&self.workspace_digest)
                && self.generation > 0
                && self.ordinal > 0
                && valid_hex(&self.token),
            "retained prefix segment locator differs",
        )
    }
}
impl PrefixSegmentHeadStampV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        require(
            self.revision == 2 && nonzero(self.map_digest) && valid_hex(&self.token),
            "prefix segment head stamp differs",
        )
    }
}
impl PrefixSegMemberV2 {
    pub(crate) fn validate(&self, m: &PrefixDeltaManifestV2) -> ServiceResult<()> {
        require(
            self.segment_ordinal == m.ordinal
                && self.segment_digest == m.content_digest
                && self.commit > m.before.through
                && self.commit <= m.after.through
                && self.ordinal < 64
                && self.profile_digest == m.after.profile_digest
                && nonzero(self.identity_digest)
                && nonzero(self.event_digest)
                && nonzero(self.vector_digest)
                && valid_hex(&self.policy_domain)
                && valid_hex(&self.token)
                && m.cohorts
                    .iter()
                    .any(|c| c.policy_domain == self.policy_domain)
                && self.span.event_id == self.source.event_id
                && Some(self.span.payload_digest) == self.source.payload_digest
                && nonzero(self.span.payload_digest)
                && nonzero(self.span.span_digest)
                && self.span.start < self.span.end
                && self
                    .source
                    .byte_length
                    .is_some_and(|end| self.span.end <= end)
                && self.source.independent_source
                && self.source.omission.is_none(),
            "prefix segment member immutable binding differs",
        )
    }
}
impl PrefixSegCohortV2 {
    pub(crate) fn validate(&self, m: &PrefixDeltaManifestV2) -> ServiceResult<()> {
        require(
            self.segment_ordinal == m.ordinal
                && self.segment_digest == m.content_digest
                && valid_hex(&self.policy_domain)
                && valid_hex(&self.token)
                && !self.policies.is_empty()
                && self.policies.len() <= 128
                && !self.partition.is_empty()
                && self.partition.len() <= ANN_V2_MAX_PARTITION_MANIFEST_BYTES
                && m.cohorts
                    .iter()
                    .any(|c| c.policy_domain == self.policy_domain),
            "prefix segment cohort immutable binding differs",
        )
    }
}
impl PrefixSegNodeV2 {
    pub(crate) fn validate(&self, m: &PrefixDeltaManifestV2) -> ServiceResult<()> {
        require(
            self.segment_ordinal == m.ordinal
                && self.segment_digest == m.content_digest
                && valid_hex(&self.policy_domain)
                && valid_hex(&self.token)
                && !self.canonical_node.is_empty()
                && self.canonical_node.len() <= ANN_V2_MAX_NODE_BYTES
                && m.cohorts
                    .iter()
                    .any(|c| c.policy_domain == self.policy_domain),
            "prefix segment node immutable binding differs",
        )
    }
}

fn bounded_vec<'de, D: Deserializer<'de>, T: Deserialize<'de>, const CAP: usize>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    struct Bound<T, const CAP: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const CAP: usize> Visitor<'de> for Bound<T, CAP> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {CAP} prefix segment entries")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            if seq.size_hint().is_some_and(|n| n > CAP) {
                return Err(de::Error::custom(
                    "prefix segment sequence exceeds its bound",
                ));
            }
            // These power-of-two caps bound geometric growth without full-capacity
            // allocations for small rows. Native point loaders prepay decoding.
            let mut values = Vec::new();
            for _ in 0..CAP {
                let Some(value) = seq.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            if seq.next_element::<de::IgnoredAny>()?.is_some() {
                return Err(de::Error::custom(
                    "prefix segment sequence exceeds its bound",
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

fn key_identity(workspace: &str, generation: u64) -> ServiceResult<()> {
    require(
        valid_hex(workspace) && generation > 0,
        "prefix segment key identity differs",
    )
}
pub(crate) fn segment_prefix(
    workspace: &str,
    generation: u64,
    ordinal: u64,
) -> ServiceResult<Vec<u8>> {
    key_identity(workspace, generation)?;
    require(ordinal > 0, "prefix segment key ordinal differs")?;
    Ok(format!(
        "{}dense/prefix-segment-v2/{ordinal:016x}/",
        crate::raw_index::generation_prefix(workspace, generation)
    )
    .into_bytes())
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
    Ok(format!(
        "{}dense/prefix-segments-v2/head",
        crate::raw_index::generation_prefix(workspace, generation)
    )
    .into_bytes())
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
    require(valid_hex(domain), "prefix segment policy key differs")?;
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
    require(ordinal > 0, "retained prefix segment ordinal differs")?;
    Ok(format!("ann-prefix-segment/v2/{workspace}/{generation:016x}/{ordinal:016x}").into_bytes())
}

#[cfg(test)]
mod tests;
