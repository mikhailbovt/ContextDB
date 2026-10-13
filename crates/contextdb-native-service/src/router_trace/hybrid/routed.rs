//! Protected coarse routing observations. Centroids are never source evidence.

use super::segments::{HybridDensePathCompletion, HybridDensePathKind, HybridDensePathObservation};
use super::{HybridCompletion, HybridRouteObservation, integrity, zero};
use crate::raw_index::dense::graph::prefix_segments_v2::types::{
    PrefixSegmentBaseRefV2, PrefixSegmentDirectoryRefV2,
};
use crate::raw_index::dense::graph::routing::types::{
    DirectoryRouterCoverageV1, DirectoryRouterFinePathV1, DirectoryRouterRefV1,
};
use contextdb_core::{ContentDigest, EventEnvelope, RepresentationId, VectorSpaceId};
use contextdb_recall::QueryBudget;
use contextdb_service::{OwnedHybridIntent, ServiceResult};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{SeqAccess, Visitor},
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const ROUTED_HYBRID_OBSERVATION_REVISION: &str =
    "contextdb.native-owned-hybrid-routed-observation.v1";
pub(crate) const ROUTED_HYBRID_FEATURE: &str = "continuous-owned-hybrid-routed-v1";
pub(crate) const ROUTED_QUOTA_REVISION: &str =
    "contextdb.native-routed-reserve-fine-fresh-actual-share.v1";

/// Exact current owner roots. The generation digest covers the real generation,
/// including its current dense state; no reduced raw census is manufactured.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridRoutedBinding {
    pub generation: u64,
    pub generation_digest: ContentDigest,
    pub base: PrefixSegmentBaseRefV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<PrefixSegmentDirectoryRefV2>,
    pub router: DirectoryRouterRefV1,
}

impl HybridRoutedBinding {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.base.validate()?;
        self.router.validate()?;
        if let Some(directory) = &self.directory {
            directory.validate()?;
        }
        if self.generation == 0
            || zero(self.generation_digest)
            || self.router.global_commit <= self.base.publication.global_commit
            || self.directory.as_ref().is_some_and(|d| {
                d.global_commit <= self.base.publication.global_commit
                    || d.global_commit >= self.router.global_commit
            })
        {
            return Err(integrity("routed current owner binding differs"));
        }
        Ok(())
    }
}

/// One actual finite coarse similarity, retained before local beam disposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridCoarseScore {
    pub representation_id: RepresentationId,
    pub identity_digest: ContentDigest,
    pub path: DirectoryRouterFinePathV1,
    pub fine_partition_digest: ContentDigest,
    pub policy_domain: String,
    pub score_bits: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridCoarseObservation {
    pub has_work: bool,
    pub max_node_reads: u32,
    pub max_vector_reads: u32,
    pub max_discovered: u32,
    pub node_reads: u64,
    pub vector_reads: u64,
    pub discovered: u64,
    pub completion: HybridDensePathCompletion,
    #[serde(deserialize_with = "scores")]
    pub scores: Vec<HybridCoarseScore>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridRoutedDenseWitness {
    pub binding: HybridRoutedBinding,
    pub coverage_count: u64,
    pub coverage_digest: ContentDigest,
    pub recipe_revision: String,
    pub quota_revision: String,
    pub source_profile_digest: ContentDigest,
    pub source_space_id: VectorSpaceId,
    pub coarse_space_digest: ContentDigest,
    pub coarse_space_id: VectorSpaceId,
    pub covered_dense_commitment: ContentDigest,
    pub observed_dense_commitment: ContentDigest,
    pub proven_dense_commitment: ContentDigest,
    pub base_through: u64,
    pub covered_through: u64,
    pub proven_through: u64,
    pub observed_dense_through: u64,
    pub raw_through: u64,
    pub coarse: HybridCoarseObservation,
    #[serde(deserialize_with = "selected_paths")]
    pub selected_paths: Vec<DirectoryRouterFinePathV1>,
    /// Whether every actually scored distinct target was selected. This is not
    /// exhaustive ANN or semantic coverage of the published directory.
    pub selection_complete: bool,
    pub unvisited_paths: bool,
    /// Selected targets in coarse rank order, then exactly one fresh-tail path.
    #[serde(deserialize_with = "paths")]
    pub paths: Vec<HybridDensePathObservation>,
}

fn scores<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<HybridCoarseScore>, D::Error> {
    struct Scores;
    impl<'de> Visitor<'de> for Scores {
        type Value = Vec<HybridCoarseScore>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most 4096 actual coarse scores")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            // No caller size_hint or up-front 4096-record reservation for an
            // empty/short trace. Growth never exceeds the admitted ANN cap.
            let mut values = Vec::new();
            while values.len() < 4096 {
                let Some(value) = sequence.next_element::<HybridCoarseScore>()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "coarse score collection exceeds bound",
                ));
            }
            Ok(values)
        }
    }
    d.deserialize_seq(Scores)
}
fn selected_paths<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<DirectoryRouterFinePathV1>, D::Error> {
    super::segments::bounded::<D, DirectoryRouterFinePathV1, 64>(d)
}
fn paths<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<HybridDensePathObservation>, D::Error> {
    super::segments::bounded::<D, HybridDensePathObservation, 65>(d)
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn compact_matches(digest: ContentDigest, id: RepresentationId) -> bool {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 15) | 128;
    bytes[8] = (bytes[8] & 63) | 128;
    !zero(digest) && id.as_uuid().as_bytes() == &bytes
}
fn space_matches(digest: ContentDigest, id: VectorSpaceId) -> bool {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 15) | 128;
    bytes[8] = (bytes[8] & 63) | 128;
    !zero(digest) && id.as_uuid().as_bytes() == &bytes
}

impl HybridRoutedDenseWitness {
    pub(super) fn validate(
        &self,
        route: &HybridRouteObservation,
        intent: &OwnedHybridIntent,
        known_at: u64,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        use HybridCompletion as C;
        use HybridDensePathCompletion as P;
        use HybridDensePathKind as K;
        parent.check().map_err(crate::raw_index::budget_error)?;
        intent.validate()?;
        let limits = intent
            .limits
            .routed
            .ok_or_else(|| integrity("routed witness lacks intent"))?;
        if self.selected_paths.len() > limits.max_fine_paths as usize
            || self.selected_paths.len() > 64
            || self.paths.len() != self.selected_paths.len() + 1
            || self.coarse.scores.len() > 4096
        {
            return Err(integrity("routed protected collection bounds differ"));
        }
        parent
            .charge(
                self.coarse.scores.len() as u64 * 1024 + self.paths.len() as u64 * 32 + 1024,
                self.coarse.scores.len() as u64 * 2048 + self.paths.len() as u64 * 2048 + 32768,
            )
            .map_err(crate::raw_index::budget_error)?;
        self.binding.validate()?;
        let coverage = DirectoryRouterCoverageV1 {
            base: self.binding.base.clone(),
            directory: self.binding.directory.clone(),
        };
        if self.coverage_count != coverage.count()?
            || zero(self.coverage_digest)
            || self.recipe_revision
                != crate::raw_index::dense::graph::routing::types::RECIPE_REVISION
            || self.quota_revision != ROUTED_QUOTA_REVISION
            || !space_matches(self.coarse_space_digest, self.coarse_space_id)
            || self.coarse_space_id == self.source_space_id
            || [
                self.source_profile_digest,
                self.coarse_space_digest,
                self.covered_dense_commitment,
                self.observed_dense_commitment,
                self.proven_dense_commitment,
            ]
            .into_iter()
            .any(zero)
            || self.base_through > self.covered_through
            || self.covered_through > self.proven_through
            || self.proven_through > self.observed_dense_through
            || self.observed_dense_through > self.raw_through
            || self.raw_through > known_at
            || route.dense_lag != (self.observed_dense_through < self.raw_through)
            || (route.tail_witness_complete && self.proven_through != self.observed_dense_through)
            || (!route.tail_witness_complete && self.proven_through != self.covered_through)
            || (self.proven_through == self.covered_through
                && self.proven_dense_commitment != self.covered_dense_commitment)
            || (self.proven_through == self.observed_dense_through
                && self.proven_dense_commitment != self.observed_dense_commitment)
            || (self.binding.directory.is_none() && self.base_through != self.covered_through)
            || self.unvisited_paths != ((self.selected_paths.len() as u64) < self.coverage_count)
        {
            return Err(integrity(
                "routed coverage, profile or fresh prefix differs",
            ));
        }
        let coarse = &self.coarse;
        if coarse.max_node_reads > limits.coarse_node_reads
            || coarse.max_vector_reads > limits.coarse_vector_reads
            || coarse.max_discovered > limits.coarse_discovered
            || coarse.node_reads > u64::from(coarse.max_node_reads)
            || coarse.vector_reads > u64::from(coarse.max_vector_reads)
            || coarse.discovered > u64::from(coarse.max_discovered)
            || coarse.vector_reads > coarse.discovered
            || coarse.scores.len() as u64 != coarse.vector_reads
            || coarse.completion == P::WorkLimit
            || (!coarse.has_work
                && (coarse.node_reads != 0 || coarse.vector_reads != 0 || coarse.discovered != 0))
            || (coarse.has_work
                && coarse.completion == P::Complete
                && (coarse.max_node_reads == 0
                    || coarse.max_vector_reads == 0
                    || coarse.max_discovered == 0))
        {
            return Err(integrity("routed coarse counts or assigned quota differ"));
        }
        let mut identities = BTreeSet::new();
        let mut distinct = BTreeMap::new();
        for score in &coarse.scores {
            score.path.validate()?;
            if !compact_matches(score.identity_digest, score.representation_id)
                || !identities.insert(score.representation_id)
                || !score.path.admitted_by(&coverage)
                || zero(score.fine_partition_digest)
                || !hex(&score.policy_domain)
                || !f32::from_bits(score.score_bits).is_finite()
            {
                return Err(integrity("routed actual coarse score identity differs"));
            }
            if let Some(path) = distinct.insert(score.path.ordinal(), &score.path)
                && path != &score.path
            {
                return Err(integrity("routed coarse targets alias an ordinal"));
            }
        }
        let mut ranked: Vec<_> = coarse.scores.iter().collect();
        ranked.sort_by(|a, b| {
            f32::from_bits(b.score_bits)
                .total_cmp(&f32::from_bits(a.score_bits))
                .then_with(|| a.representation_id.cmp(&b.representation_id))
        });
        let mut selected_ordinals = BTreeSet::new();
        let mut selected = Vec::with_capacity(limits.max_fine_paths as usize);
        for score in ranked {
            if selected_ordinals.insert(score.path.ordinal())
                && selected.len() < limits.max_fine_paths as usize
            {
                selected.push(&score.path);
            }
        }
        if selected.len() != self.selected_paths.len()
            || selected
                .iter()
                .zip(&self.selected_paths)
                .any(|(a, b)| *a != b)
            || self.selection_complete != (self.selected_paths.len() == distinct.len())
        {
            return Err(integrity(
                "routed target selection differs from actual finite scores",
            ));
        }
        let (mut nodes, mut vectors, mut discovered) =
            (coarse.node_reads, coarse.vector_reads, coarse.discovered);
        let mut path_incomplete = coarse.completion != P::Complete;
        for (index, path) in self.paths.iter().enumerate() {
            let fresh = index == self.selected_paths.len();
            let (kind, ordinal) = if fresh {
                (K::FreshTail, None)
            } else {
                match &self.selected_paths[index] {
                    DirectoryRouterFinePathV1::Base { .. } => (K::Base, None),
                    DirectoryRouterFinePathV1::Segment { ordinal, .. } => {
                        (K::Segment, Some(*ordinal))
                    }
                }
            };
            if path.kind != kind
                || path.ordinal != ordinal
                || u64::from(path.max_node_reads)
                    > u64::from(intent.limits.node_reads).saturating_sub(nodes)
                || u64::from(path.max_vector_reads)
                    > u64::from(intent.limits.vector_reads).saturating_sub(vectors)
                || u64::from(path.max_discovered)
                    > u64::from(intent.limits.discovered).saturating_sub(discovered)
                || path.node_reads > u64::from(path.max_node_reads)
                || path.vector_reads > u64::from(path.max_vector_reads)
                || path.discovered > u64::from(path.max_discovered)
                || path.work > u64::from(path.max_work)
                || (!fresh
                    && (path.max_work != 0 || path.work != 0 || path.completion == P::WorkLimit))
                || (fresh
                    && (path.max_node_reads != 0
                        || path.node_reads != 0
                        || path.max_work != intent.limits.tail_work
                        || path.vector_reads > u64::from(intent.limits.tail_vectors)))
                || (!path.has_work
                    && (path.node_reads != 0 || path.vector_reads != 0 || path.discovered != 0))
                || (path.has_work
                    && path.completion == P::Complete
                    && (path.max_vector_reads == 0
                        || path.max_discovered == 0
                        || (!fresh && path.max_node_reads == 0)))
                || (fresh && path.completion == P::NodeLimit)
            {
                return Err(integrity(
                    "routed fine path or actual remaining quota differs",
                ));
            }
            nodes = nodes
                .checked_add(path.node_reads)
                .ok_or_else(|| integrity("routed node total overflow"))?;
            vectors = vectors
                .checked_add(path.vector_reads)
                .ok_or_else(|| integrity("routed vector total overflow"))?;
            discovered = discovered
                .checked_add(path.discovered)
                .ok_or_else(|| integrity("routed discovery total overflow"))?;
            path_incomplete |= path.completion != P::Complete;
            if fresh
                && (route.tail_vector_reads != path.vector_reads
                    || (!route.tail_witness_complete
                        && (!path.has_work || path.completion != P::WorkLimit))
                    || (route.tail_witness_complete && path.completion == P::WorkLimit)
                    || route.tail_scoring_complete
                        != (route.tail_witness_complete && path.completion == P::Complete))
            {
                return Err(integrity(
                    "routed fresh completion differs from proved work",
                ));
            }
        }
        if nodes != route.node_reads
            || vectors != route.vector_reads
            || discovered != route.discovered
            || (path_incomplete && !route.source_coverage_incomplete)
            || (route.completion == C::Complete && path_incomplete)
            || ((route.raw_lag
                || route.dense_lag
                || !route.tail_witness_complete
                || !route.tail_scoring_complete)
                && !route.source_coverage_incomplete)
        {
            return Err(integrity("routed global totals or completion differ"));
        }
        let fresh = self
            .paths
            .last()
            .ok_or_else(|| integrity("routed fresh path absent"))?;
        let limiting = match route.completion {
            C::Complete => true,
            C::RawLag => route.raw_lag,
            C::DenseLag => route.dense_lag,
            C::TailWorkLimit => fresh.completion == P::WorkLimit,
            C::TailVectorLimit => fresh.completion == P::VectorLimit,
            C::VectorLimit => {
                coarse.completion == P::VectorLimit
                    || self.paths.iter().any(|p| p.completion == P::VectorLimit)
            }
            C::DiscoveryLimit => {
                coarse.completion == P::DiscoveryLimit
                    || self.paths.iter().any(|p| p.completion == P::DiscoveryLimit)
            }
            C::BaseLimit => {
                coarse.completion == P::NodeLimit
                    || self.paths.iter().any(|p| p.completion == P::NodeLimit)
            }
            _ => false,
        };
        if !limiting {
            return Err(integrity(
                "routed completion has no recorded limiting stage",
            ));
        }
        Ok(())
    }
}

/// One streaming discovery pass for both additive modes. Markers declare format
/// support only; the sealed complete observation proves its actual encoding.
pub(crate) fn event_hybrid_query_modes(event: &EventEnvelope) -> ServiceResult<(bool, bool)> {
    let Some(pages) = super::protected_pages(event)? else {
        return Ok((false, false));
    };
    #[derive(Deserialize)]
    struct Marker {
        #[serde(default)]
        owned_hybrid: Option<Observation>,
    }
    #[derive(Deserialize)]
    struct Observation {
        revision: Revision,
        intent: Intent,
    }
    struct Revision(bool, bool);
    impl<'de> Deserialize<'de> for Revision {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Compare;
            impl Visitor<'_> for Compare {
                type Value = Revision;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("protected hybrid revision")
                }
                fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Revision, E> {
                    Ok(Revision(
                        s == super::segments::SEGMENTED_HYBRID_OBSERVATION_REVISION,
                        s == ROUTED_HYBRID_OBSERVATION_REVISION,
                    ))
                }
            }
            d.deserialize_str(Compare)
        }
    }
    #[derive(Deserialize)]
    struct Intent {
        limits: Limits,
    }
    #[derive(Deserialize)]
    struct Limits {
        #[serde(default)]
        segments: Option<serde::de::IgnoredAny>,
        #[serde(default)]
        routed: Option<serde::de::IgnoredAny>,
    }
    let marker: Marker = serde_json::from_reader(pages)
        .map_err(|_| integrity("hybrid mode marker has malformed protected JSON"))?;
    Ok(marker.owned_hybrid.map_or((false, false), |o| {
        (
            o.revision.0 || o.intent.limits.segments.is_some(),
            o.revision.1 || o.intent.limits.routed.is_some(),
        )
    }))
}
#[cfg(test)]
mod tests;
