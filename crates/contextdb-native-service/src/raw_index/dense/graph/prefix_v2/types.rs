//! Prefix shapes and addresses. Validation does not grant acceptance or current access.

use std::fmt;

use contextdb_core::{ContentDigest, OriginalSourceSpan, RawSource, RepresentationId};
use contextdb_index::{
    ANN_PARTITION_BUILD_REVISION_V2, ANN_V2_MAX_NODE_BYTES, ANN_V2_MAX_PARTITION_MANIFEST_BYTES,
    RAW_ANALYZER,
};
use contextdb_recall::QueryBudget;
use contextdb_service::{AccessPolicy, ServiceResult};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};

use super::super::{GraphCohortSummary, segments::types::AcceptedPublicationRef};
use crate::{
    integrity,
    raw_index::{
        Generation,
        bm25::Bm25Profile,
        budget_error,
        dense::{DenseManifest, DenseProjectionReceipt},
    },
};

pub(crate) const FEATURE: &str = "continuous-raw-span-ann-prefix-v2";
pub(crate) const OPERATION: &str = "raw_span_ann_prefix_v2";
pub(crate) const MAX_WORK: u32 = 128;
pub(crate) const MAX_NODES: u64 = 4096;
pub(crate) const MAX_COHORTS: usize = 64;
pub(crate) const ROW_BYTES: usize = 128 * 1024;
/// Bounds the numeric-byte primary idempotency envelope as well as its inner response.
pub(crate) const MAX_PUBLICATION_BYTES: usize = (ROW_BYTES - 4096) / 4;
pub(crate) const KEY_BYTES: u64 = 1024;
pub(crate) const INTERVAL_DOMAIN: &[u8] = b"contextdb.native-span-ann-prefix-interval.v2\0";
pub(crate) const FINAL_DOMAIN: &[u8] = b"contextdb.native-span-ann-prefix-final.v2\0";
pub(crate) const RECEIPT_MAC: &[u8] = b"contextdb.native-span-ann-prefix-receipt.v2\0";
pub(crate) const MEMBER_MAC: &[u8] = b"contextdb.native-span-ann-prefix-member.v2\0";
pub(crate) const COHORT_MAC: &[u8] = b"contextdb.native-span-ann-prefix-cohort.v2\0";
pub(crate) const NODE_MAC: &[u8] = b"contextdb.native-span-ann-prefix-node.v2\0";
pub(crate) const LOCATOR_MAC: &[u8] = b"contextdb.native-span-ann-prefix-locator.v2\0";
pub(crate) const WORKSPACE_HEADS_MAC: &[u8] =
    b"contextdb.native-span-ann-prefix-workspace-heads.v2\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrefixRawBindingV2 {
    pub(crate) generation: u64,
    pub(crate) custody_version: u16,
    pub(crate) analyzer: String,
    pub(crate) bm25: Bm25Profile,
    pub(crate) authorization_epoch: u64,
    pub(crate) removal_through: Option<u64>,
    pub(crate) through: u64,
    pub(crate) projected_sources: u64,
}
impl PrefixRawBindingV2 {
    pub(crate) fn from_generation(g: &Generation, parent: &mut QueryBudget) -> ServiceResult<Self> {
        let bm25 = g
            .bm25
            .as_ref()
            .ok_or_else(|| integrity("prefix requires a real BM25 generation"))?;
        let bytes = super::crypto::metered_json_len(
            &(
                g.number,
                g.custody_version,
                &g.analyzer,
                bm25,
                g.authorization_epoch,
                g.removal_through,
                g.through,
                g.projected_sources,
            ),
            parent,
            ROW_BYTES,
        )?;
        parent
            .charge(1, bytes as u64 * 16 + 4096)
            .map_err(budget_error)?;
        let binding = Self {
            generation: g.number,
            custody_version: g.custody_version,
            analyzer: g.analyzer.clone(),
            bm25: bm25.clone(),
            authorization_epoch: g.authorization_epoch,
            removal_through: g.removal_through,
            through: g.through,
            projected_sources: g.projected_sources,
        };
        binding.validate()?;
        Ok(binding)
    }
    pub(crate) fn matches_generation(&self, g: &Generation) -> bool {
        self.generation == g.number
            && self.custody_version == g.custody_version
            && self.analyzer == g.analyzer
            && Some(&self.bm25) == g.bm25.as_ref()
            && self.authorization_epoch == g.authorization_epoch
            && self.removal_through == g.removal_through
            && self.through == g.through
            && self.projected_sources == g.projected_sources
    }
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.bm25.validate()?;
        require(
            self.generation > 0
                && self.custody_version == crate::custody::CUSTODY_VERSION
                && self.analyzer == RAW_ANALYZER
                && self.authorization_epoch.checked_add(1).is_some()
                && self.through > 0
                && self.projected_sources <= self.through,
            "prefix real raw binding differs",
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrefixIntervalV2 {
    pub(crate) work_items: u32,
    pub(crate) digest: ContentDigest,
}

/// Explicit current target/CAS identity. A caller receipt is not native authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DensePrefixBaseRequestV2 {
    /// Actual active raw generation; its full counters are never rewritten.
    pub generation: u64,
    /// Exact current owner-accepted dense receipt for initial publication.
    pub target: DenseProjectionReceipt,
}
impl DensePrefixBaseRequestV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        let t = &self.target;
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
                && t.embedded_sources.checked_add(t.omitted_sources) == Some(t.sources)
                && t.sources <= t.through
                && t.spans >= t.embedded_sources
                && t.embedded_sources
                    .checked_mul(64)
                    .is_some_and(|cap| t.spans <= cap)
                && t.caught_up == (t.through == t.raw_through)
                && (t.through != t.raw_through || t.sources == t.raw_sources)
                && t.profile_digest == t.profile.digest()?
                && nonzero(t.commitment),
            "prefix target shape differs",
        )
    }
}

/// Complete real dense prefix and immutable topology; this is a maintenance format.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DensePrefixBaseManifestV2 {
    pub(crate) revision: u16,
    pub(crate) raw: PrefixRawBindingV2,
    pub(crate) admitted_known_at: u64,
    pub(crate) admitted_global_commit: u64,
    pub(crate) target: AcceptedPublicationRef,
    pub(crate) prefix: DenseManifest,
    pub(crate) interval: PrefixIntervalV2,
    pub(crate) nodes: u64,
    #[serde(deserialize_with = "bounded_cohorts")]
    pub(crate) cohorts: Vec<GraphCohortSummary>,
    pub(crate) builder_revision: String,
    pub(crate) content_digest: ContentDigest,
}
impl DensePrefixBaseManifestV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.raw.validate()?;
        self.target.validate()?;
        self.prefix.validate(self.raw.through)?;
        let total = self
            .cohorts
            .iter()
            .try_fold(0_u64, |sum, c| sum.checked_add(c.nodes));
        require(
            self.revision == 2
                && self.admitted_known_at >= self.raw.through
                && self
                    .raw
                    .removal_through
                    .is_none_or(|at| at <= self.admitted_known_at)
                && self.admitted_global_commit >= self.admitted_known_at
                && self.target.global_commit <= self.admitted_global_commit
                && (1..=MAX_WORK).contains(&self.interval.work_items)
                && u64::from(self.interval.work_items) <= self.prefix.through
                && self.prefix.sources <= u64::from(self.interval.work_items)
                && self.prefix.sources <= self.raw.projected_sources
                && (self.prefix.through != self.raw.through
                    || self.prefix.sources == self.raw.projected_sources)
                && (1..=MAX_NODES).contains(&self.nodes)
                && self.nodes == self.prefix.spans
                && !self.cohorts.is_empty()
                && self.cohorts.len() <= MAX_COHORTS
                && total == Some(self.nodes)
                && self
                    .cohorts
                    .windows(2)
                    .all(|p| p[0].policy_domain < p[1].policy_domain)
                && self.cohorts.iter().all(|c| {
                    valid_hex(&c.policy_domain)
                        && (1..=MAX_NODES).contains(&c.nodes)
                        && nonzero(c.partition_digest)
                })
                && self.builder_revision == ANN_PARTITION_BUILD_REVISION_V2
                && nonzero(self.prefix.commitment)
                && nonzero(self.interval.digest)
                && nonzero(self.content_digest),
            "prefix immutable manifest differs",
        )
    }
}

/// Native-issued immutable prefix acceptance; its MAC grants no serving access.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DensePrefixBaseReceiptV2 {
    /// Native database identity.
    pub database_id: String,
    /// Workspace owning the accepted prefix.
    pub workspace_id: String,
    /// Full real raw binding, accepted dense target and final graph commitment.
    pub manifest: DensePrefixBaseManifestV2,
    /// Actual native publication position.
    pub global_commit: u64,
    /// Owner authentication over this exact full receipt.
    pub token: String,
}
impl DensePrefixBaseReceiptV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.manifest.validate()?;
        require(
            valid_name(&self.database_id)
                && valid_name(&self.workspace_id)
                && self.global_commit > self.manifest.admitted_global_commit
                && valid_hex(&self.token),
            "prefix receipt shape differs",
        )
    }
}

/// Current map reference omits its own event digest to avoid a stamp/hash cycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixBaseRefV2 {
    pub(crate) global_commit: u64,
    pub(crate) request_digest: String,
    pub(crate) response_digest: String,
    pub(crate) receipt_digest: ContentDigest,
    pub(crate) content_digest: ContentDigest,
}
impl PrefixBaseRefV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        require(
            self.global_commit > 0
                && valid_hex(&self.request_digest)
                && valid_hex(&self.response_digest)
                && nonzero(self.receipt_digest)
                && nonzero(self.content_digest),
            "prefix root reference differs",
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrefixBaseStampV2 {
    pub(crate) revision: u16,
    pub(crate) map_digest: ContentDigest,
    pub(crate) token: String,
}
impl PrefixBaseStampV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        require(
            self.revision == 2 && nonzero(self.map_digest) && valid_hex(&self.token),
            "prefix root stamp differs",
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedPrefixBaseLocatorV2 {
    pub(crate) revision: u16,
    pub(crate) workspace_digest: String,
    pub(crate) generation: u64,
    pub(crate) publication: AcceptedPublicationRef,
    pub(crate) token: String,
}
impl RetainedPrefixBaseLocatorV2 {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.publication.validate()?;
        require(
            self.revision == 2
                && valid_hex(&self.workspace_digest)
                && self.generation > 0
                && valid_hex(&self.token),
            "retained prefix locator differs",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrefixMemberV2 {
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
    pub(crate) prefix_digest: ContentDigest,
    pub(crate) token: String,
}
impl PrefixMemberV2 {
    pub(crate) fn validate(&self, m: &DensePrefixBaseManifestV2) -> ServiceResult<()> {
        require(
            self.prefix_digest == m.content_digest
                && self.commit > 0
                && self.commit <= m.prefix.through
                && self.ordinal < 64
                && self.profile_digest == m.prefix.profile_digest
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
            "prefix member source binding differs",
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrefixCohortV2 {
    pub(crate) policy_domain: String,
    #[serde(deserialize_with = "bounded_policies")]
    pub(crate) policies: Vec<AccessPolicy>,
    #[serde(deserialize_with = "bounded_partition")]
    pub(crate) partition: Vec<u8>,
    pub(crate) prefix_digest: ContentDigest,
    pub(crate) token: String,
}
impl PrefixCohortV2 {
    pub(crate) fn validate(&self, m: &DensePrefixBaseManifestV2) -> ServiceResult<()> {
        require(
            self.prefix_digest == m.content_digest
                && valid_hex(&self.policy_domain)
                && valid_hex(&self.token)
                && !self.policies.is_empty()
                && self.policies.len() <= 128
                && !self.partition.is_empty()
                && self.partition.len() <= ANN_V2_MAX_PARTITION_MANIFEST_BYTES
                && m.cohorts
                    .iter()
                    .any(|c| c.policy_domain == self.policy_domain),
            "prefix cohort shape differs",
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrefixNodeV2 {
    pub(crate) representation_id: RepresentationId,
    pub(crate) policy_domain: String,
    #[serde(deserialize_with = "bounded_node")]
    pub(crate) canonical_node: Vec<u8>,
    pub(crate) prefix_digest: ContentDigest,
    pub(crate) token: String,
}
impl PrefixNodeV2 {
    pub(crate) fn validate(&self, m: &DensePrefixBaseManifestV2) -> ServiceResult<()> {
        require(
            self.prefix_digest == m.content_digest
                && valid_hex(&self.policy_domain)
                && valid_hex(&self.token)
                && !self.canonical_node.is_empty()
                && self.canonical_node.len() <= ANN_V2_MAX_NODE_BYTES
                && m.cohorts
                    .iter()
                    .any(|c| c.policy_domain == self.policy_domain),
            "prefix node shape differs",
        )
    }
}

pub(crate) fn valid_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn nonzero(d: ContentDigest) -> bool {
    d.as_bytes() != &[0; 32]
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
            write!(f, "at most {CAP} prefix entries")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            if seq.size_hint().is_some_and(|n| n > CAP) {
                return Err(de::Error::custom("prefix sequence exceeds its bound"));
            }
            // All caps here are powers of two. Doubling cannot exceed the cap;
            // small rows do not allocate a full maximum-size byte buffer.
            let mut values = Vec::new();
            for _ in 0..CAP {
                let Some(value) = seq.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            if seq.next_element::<de::IgnoredAny>()?.is_some() {
                return Err(de::Error::custom("prefix sequence exceeds its bound"));
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

pub(crate) fn prefix_key(workspace: &str, generation: u64) -> ServiceResult<Vec<u8>> {
    require(
        valid_hex(workspace) && generation > 0,
        "prefix key identity differs",
    )?;
    Ok(format!(
        "{}dense/prefix-base-v2/",
        crate::raw_index::generation_prefix(workspace, generation)
    )
    .into_bytes())
}
pub(crate) fn receipt_key(workspace: &str, generation: u64) -> ServiceResult<Vec<u8>> {
    let mut key = prefix_key(workspace, generation)?;
    key.extend_from_slice(b"receipt");
    Ok(key)
}
pub(crate) fn member_key(
    workspace: &str,
    generation: u64,
    id: RepresentationId,
) -> ServiceResult<Vec<u8>> {
    let mut key = prefix_key(workspace, generation)?;
    key.extend_from_slice(format!("member/{id}").as_bytes());
    Ok(key)
}
pub(crate) fn cohort_key(workspace: &str, generation: u64, domain: &str) -> ServiceResult<Vec<u8>> {
    require(valid_hex(domain), "prefix policy key differs")?;
    let mut key = prefix_key(workspace, generation)?;
    key.extend_from_slice(format!("cohort/{domain}").as_bytes());
    Ok(key)
}
pub(crate) fn node_key(
    workspace: &str,
    generation: u64,
    id: RepresentationId,
) -> ServiceResult<Vec<u8>> {
    let mut key = prefix_key(workspace, generation)?;
    key.extend_from_slice(format!("node/{id}").as_bytes());
    Ok(key)
}
pub(crate) fn retained_locator_key(workspace: &str, generation: u64) -> ServiceResult<Vec<u8>> {
    require(
        valid_hex(workspace) && generation > 0,
        "retained prefix key identity differs",
    )?;
    Ok(format!("ann-prefix/v2/{workspace}/{generation:016x}").into_bytes())
}

#[cfg(test)]
mod tests;
