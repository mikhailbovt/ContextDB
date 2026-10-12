//! Protected segmented discovery observations. No cuts or caps in this module
//! become reader controls, current source grants, or whole-database success.

use super::{HybridCompletion, HybridRouteObservation, integrity, zero};
use contextdb_core::{ContentDigest, EventEnvelope};
use contextdb_recall::QueryBudget;
use contextdb_service::{OwnedHybridIntent, ServiceResult};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{SeqAccess, Visitor},
};

pub(crate) const SEGMENTED_HYBRID_OBSERVATION_REVISION: &str =
    "contextdb.native-owned-hybrid-segments-observation.v1";
pub(crate) const SEGMENTED_HYBRID_FEATURE: &str = "continuous-owned-hybrid-segments-v1";
pub(crate) const SEGMENT_QUOTA_REVISION: &str = "native-segment-fair-remaining-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridSegmentBaseIdentity {
    pub global_commit: u64,
    pub event_digest: String,
    pub request_digest: String,
    pub response_digest: String,
    pub receipt_digest: ContentDigest,
    pub graph_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridSegmentDirectoryIdentity {
    pub count: u64,
    pub global_commit: u64,
    pub request_digest: String,
    pub response_digest: String,
    pub content_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridSegmentLatestIdentity {
    pub ordinal: u64,
    pub global_commit: u64,
    pub manifest_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HybridDensePathKind {
    Base,
    Segment,
    FreshTail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HybridDensePathCompletion {
    Complete,
    NodeLimit,
    VectorLimit,
    DiscoveryLimit,
    WorkLimit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridDensePathObservation {
    pub kind: HybridDensePathKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u64>,
    /// Owner-observed permitted scoring work, conservatively true while the
    /// fresh witness is incomplete. Omitted or forbidden documents alone do not
    /// constitute scoring work. This grants no source authority.
    pub has_work: bool,
    pub max_node_reads: u32,
    pub max_vector_reads: u32,
    pub max_discovered: u32,
    pub max_work: u32,
    pub node_reads: u64,
    pub vector_reads: u64,
    pub discovered: u64,
    pub work: u64,
    pub completion: HybridDensePathCompletion,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridSegmentedDenseWitness {
    pub base: HybridSegmentBaseIdentity,
    /// The first vertical requires an admitted existing segmented directory.
    pub head: HybridSegmentDirectoryIdentity,
    pub latest: HybridSegmentLatestIdentity,
    pub covered_dense_commitment: ContentDigest,
    pub observed_dense_commitment: ContentDigest,
    pub proven_dense_commitment: ContentDigest,
    pub base_through: u64,
    pub covered_through: u64,
    pub observed_dense_through: u64,
    pub proven_through: u64,
    pub raw_through: u64,
    pub quota_revision: String,
    #[serde(deserialize_with = "selected_ordinals")]
    pub selected_ordinals: Vec<u64>,
    pub selection_complete: bool,
    #[serde(deserialize_with = "paths")]
    pub paths: Vec<HybridDensePathObservation>,
}

fn bounded<'de, D: Deserializer<'de>, T: Deserialize<'de>, const CAP: usize>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    struct Bound<T, const CAP: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const CAP: usize> Visitor<'de> for Bound<T, CAP> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {CAP} protected segment entries")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<T>, A::Error> {
            // A constant allocation, never a caller-controlled size_hint or a
            // doubling reserve beyond the fixed number of admitted entries.
            let mut values = Vec::with_capacity(CAP);
            while values.len() < CAP {
                let Some(value) = sequence.next_element::<T>()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "protected segment collection exceeds bound",
                ));
            }
            Ok(values)
        }
    }
    d.deserialize_seq(Bound::<T, CAP>(std::marker::PhantomData))
}
fn selected_ordinals<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u64>, D::Error> {
    bounded::<D, u64, 64>(d)
}
fn paths<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<HybridDensePathObservation>, D::Error> {
    bounded::<D, HybridDensePathObservation, 66>(d)
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl HybridSegmentedDenseWitness {
    pub(super) fn validate(
        &self,
        route: &HybridRouteObservation,
        intent: &OwnedHybridIntent,
        known_at: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        use HybridCompletion as C;
        use HybridDensePathCompletion as P;
        use HybridDensePathKind as K;
        let limits = intent
            .limits
            .segments
            .ok_or_else(|| integrity("segmented witness has no segment intent"))?;
        if self.selected_ordinals.is_empty()
            || self.selected_ordinals.len() > 64
            || self.selected_ordinals.len() > limits.max_segments as usize
            || self.paths.len() != self.selected_ordinals.len() + 2
            || self.paths.len() > 66
        {
            return Err(integrity("segmented witness collection bounds differ"));
        }
        budget
            .charge(
                self.paths.len() as u64 + 16,
                self.paths.len() as u64 * 1024 + self.selected_ordinals.len() as u64 * 32 + 8192,
            )
            .map_err(crate::raw_index::budget_error)?;
        if self.quota_revision != SEGMENT_QUOTA_REVISION
            || self.base.global_commit == 0
            || self.head.count == 0
            || self.head.global_commit <= self.base.global_commit
            || self.latest.global_commit != self.head.global_commit
            || self.latest.ordinal != self.head.count
            || ![
                &self.base.event_digest,
                &self.base.request_digest,
                &self.base.response_digest,
                &self.head.request_digest,
                &self.head.response_digest,
            ]
            .into_iter()
            .all(|s| hex(s))
            || [
                self.base.receipt_digest,
                self.base.graph_digest,
                self.head.content_digest,
                self.latest.manifest_digest,
                self.latest.receipt_digest,
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
            || self
                .selected_ordinals
                .iter()
                .enumerate()
                .any(|(index, ordinal)| *ordinal != index as u64 + 1 || *ordinal > self.head.count)
            || self.selection_complete != (self.selected_ordinals.len() as u64 == self.head.count)
        {
            return Err(integrity(
                "segmented witness identities, prefix or selection disagree",
            ));
        }
        let (mut nodes, mut vectors, mut discovered) = (0_u64, 0_u64, 0_u64);
        let mut path_incomplete = false;
        for (index, path) in self.paths.iter().enumerate() {
            let fresh = index == self.paths.len() - 1;
            let kind = if index == 0 {
                K::Base
            } else if fresh {
                K::FreshTail
            } else {
                K::Segment
            };
            let ordinal = if kind == K::Segment {
                Some(self.selected_ordinals[index - 1])
            } else {
                None
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
                    "segmented witness path order, work or remaining quota differs",
                ));
            }
            nodes += path.node_reads;
            vectors += path.vector_reads;
            discovered += path.discovered;
            path_incomplete |= path.completion != P::Complete;
            if fresh
                && (route.tail_vector_reads != path.vector_reads
                    || (!route.tail_witness_complete
                        && (!path.has_work || path.completion != P::WorkLimit))
                    || (route.tail_witness_complete && path.completion == P::WorkLimit)
                    || (route.tail_scoring_complete
                        != (route.tail_witness_complete && path.completion == P::Complete)))
            {
                return Err(integrity(
                    "segmented fresh-tail completion differs from proved work",
                ));
            }
        }
        if nodes != route.node_reads
            || vectors != route.vector_reads
            || discovered != route.discovered
            || (!self.selection_complete && !route.source_coverage_incomplete)
            || (path_incomplete && !route.source_coverage_incomplete)
            || (route.completion == C::Complete && (!self.selection_complete || path_incomplete))
            || (route.completion == C::SegmentSelectionLimit && self.selection_complete)
            || ((route.raw_lag
                || route.dense_lag
                || !route.tail_witness_complete
                || !route.tail_scoring_complete)
                && !route.source_coverage_incomplete)
        {
            return Err(integrity(
                "segmented route totals or incomplete-selection claim disagree",
            ));
        }
        let fresh = self
            .paths
            .last()
            .ok_or_else(|| integrity("segmented route fresh path absent"))?;
        let reason_exists = match route.completion {
            C::Complete => true,
            C::SegmentSelectionLimit => !self.selection_complete,
            C::RawLag => route.raw_lag,
            C::DenseLag => route.dense_lag,
            C::TailWorkLimit => fresh.completion == P::WorkLimit,
            C::TailVectorLimit => fresh.completion == P::VectorLimit,
            C::VectorLimit => self
                .paths
                .iter()
                .any(|path| path.completion == P::VectorLimit),
            C::DiscoveryLimit => self
                .paths
                .iter()
                .any(|path| path.completion == P::DiscoveryLimit),
            C::BaseLimit => self.paths[..self.paths.len() - 1]
                .iter()
                .any(|path| path.completion != P::Complete),
            _ => false,
        };
        if !reason_exists {
            return Err(integrity(
                "segmented aggregate completion has no recorded limiting path",
            ));
        }
        Ok(())
    }
}

/// Conservative retained-format discovery. Admission validates the entire
/// observation separately; this streaming marker never establishes authority.
pub(crate) fn event_has_segmented_hybrid(event: &EventEnvelope) -> ServiceResult<bool> {
    let Some(pages) = super::protected_pages(event)? else {
        return Ok(false);
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
    struct Revision(bool);
    impl<'de> Deserialize<'de> for Revision {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Compare;
            impl<'de> Visitor<'de> for Compare {
                type Value = Revision;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("protected observation revision")
                }
                fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Revision, E> {
                    Ok(Revision(s == SEGMENTED_HYBRID_OBSERVATION_REVISION))
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
    }
    let marker: Marker = serde_json::from_reader(pages)
        .map_err(|_| integrity("segmented hybrid marker has malformed protected JSON"))?;
    Ok(marker.owned_hybrid.is_some_and(|observation| {
        observation.revision.0 || observation.intent.limits.segments.is_some()
    }))
}

#[cfg(test)]
mod tests {
    //! Scalar witness proofs only; no index, encoder or semantic-recall claim.
    use super::*;
    use contextdb_core::{ModelCallId, ObservationId};
    use contextdb_service::{OwnedHybridLimits, OwnedSegmentLimits};
    use std::{collections::BTreeSet, time::Duration};

    fn digest(byte: u8) -> ContentDigest {
        ContentDigest::from_bytes([byte; 32])
    }
    fn budget() -> QueryBudget {
        QueryBudget::new(
            100_000,
            1024 * 1024,
            Duration::from_secs(30),
            Default::default(),
        )
    }
    fn fixture() -> (
        HybridSegmentedDenseWitness,
        HybridRouteObservation,
        OwnedHybridIntent,
    ) {
        let intent = OwnedHybridIntent {
            call_id: ModelCallId::new(),
            request_event: ObservationId::new(),
            interaction_sequence: 1,
            attempt: 0,
            limits: OwnedHybridLimits {
                segments: Some(OwnedSegmentLimits { max_segments: 2 }),
                ..Default::default()
            },
        };
        let paths = [
            HybridDensePathKind::Base,
            HybridDensePathKind::Segment,
            HybridDensePathKind::Segment,
            HybridDensePathKind::FreshTail,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| HybridDensePathObservation {
            kind,
            ordinal: (kind == HybridDensePathKind::Segment).then_some(index as u64),
            has_work: true,
            max_node_reads: if kind == HybridDensePathKind::FreshTail {
                0
            } else {
                256 - index as u32 * 2
            },
            max_vector_reads: 256 - index as u32 * 2,
            max_discovered: 256 - index as u32 * 2,
            max_work: if kind == HybridDensePathKind::FreshTail {
                128
            } else {
                0
            },
            node_reads: if kind == HybridDensePathKind::FreshTail {
                0
            } else {
                2
            },
            vector_reads: 2,
            discovered: 2,
            work: if kind == HybridDensePathKind::FreshTail {
                1
            } else {
                0
            },
            completion: HybridDensePathCompletion::Complete,
        })
        .collect();
        let witness = HybridSegmentedDenseWitness {
            base: HybridSegmentBaseIdentity {
                global_commit: 10,
                event_digest: "a".repeat(64),
                request_digest: "b".repeat(64),
                response_digest: "c".repeat(64),
                receipt_digest: digest(1),
                graph_digest: digest(2),
            },
            head: HybridSegmentDirectoryIdentity {
                count: 2,
                global_commit: 20,
                request_digest: "d".repeat(64),
                response_digest: "e".repeat(64),
                content_digest: digest(3),
            },
            latest: HybridSegmentLatestIdentity {
                ordinal: 2,
                global_commit: 20,
                manifest_digest: digest(4),
                receipt_digest: digest(5),
            },
            covered_dense_commitment: digest(6),
            observed_dense_commitment: digest(7),
            proven_dense_commitment: digest(7),
            base_through: 1,
            covered_through: 3,
            observed_dense_through: 4,
            proven_through: 4,
            raw_through: 4,
            quota_revision: SEGMENT_QUOTA_REVISION.into(),
            selected_ordinals: vec![1, 2],
            selection_complete: true,
            paths,
        };
        let route = HybridRouteObservation {
            route: super::super::HybridRouteKind::Dense,
            admitted_sources: BTreeSet::new(),
            ranked_sources: 0,
            completion: HybridCompletion::Complete,
            source_coverage_incomplete: false,
            raw_lag: false,
            dense_lag: false,
            tail_witness_complete: true,
            tail_scoring_complete: true,
            node_reads: 6,
            vector_reads: 8,
            discovered: 8,
            tail_vector_reads: 2,
            dense_witness: None,
            segmented_dense_witness: None,
        };
        (witness, route, intent)
    }

    #[test]
    fn unused_caps_can_be_reassigned_but_actual_global_totals_cannot() {
        let (witness, mut route, intent) = fixture();
        assert!(
            witness
                .paths
                .iter()
                .map(|p| p.max_vector_reads)
                .sum::<u32>()
                > intent.limits.vector_reads
        );
        witness
            .validate(&route, &intent, 4, &mut budget())
            .expect("reassigned unused quota");
        let mut forged = witness.clone();
        forged.paths[1].max_vector_reads = 255;
        assert!(forged.validate(&route, &intent, 4, &mut budget()).is_err());
        forged = witness.clone();
        forged.paths[1].vector_reads = u64::MAX;
        assert!(forged.validate(&route, &intent, 4, &mut budget()).is_err());
        route.vector_reads += 1;
        assert!(witness.validate(&route, &intent, 4, &mut budget()).is_err());
    }

    #[test]
    fn limited_segment_selection_is_an_explicit_incomplete_prefix() {
        let (mut witness, mut route, intent) = fixture();
        witness.selected_ordinals.pop();
        witness.paths.remove(2);
        witness.selection_complete = false;
        route.node_reads -= 2;
        route.vector_reads -= 2;
        route.discovered -= 2;
        route.source_coverage_incomplete = true;
        route.completion = HybridCompletion::SegmentSelectionLimit;
        witness
            .validate(&route, &intent, 4, &mut budget())
            .expect("honest prefix cap");
        route.completion = HybridCompletion::Complete;
        assert!(witness.validate(&route, &intent, 4, &mut budget()).is_err());
        let (mut hole, route, intent) = fixture();
        hole.head.count = 3;
        hole.latest.ordinal = 3;
        hole.selection_complete = false;
        hole.selected_ordinals = vec![1, 3];
        hole.paths[2].ordinal = Some(3);
        assert!(hole.validate(&route, &intent, 4, &mut budget()).is_err());
    }

    #[test]
    fn fresh_incomplete_proof_anchors_covered_prefix_and_omissions_need_no_vectors() {
        let (mut witness, mut route, intent) = fixture();
        let fresh = witness.paths.last_mut().expect("fresh");
        fresh.completion = HybridDensePathCompletion::WorkLimit;
        fresh.vector_reads = 0;
        fresh.discovered = 0;
        fresh.work = 128;
        witness.proven_through = witness.covered_through;
        witness.proven_dense_commitment = witness.covered_dense_commitment;
        route.vector_reads = 6;
        route.discovered = 6;
        route.tail_vector_reads = 0;
        route.tail_witness_complete = false;
        route.tail_scoring_complete = false;
        route.source_coverage_incomplete = true;
        route.completion = HybridCompletion::TailWorkLimit;
        witness
            .validate(&route, &intent, 4, &mut budget())
            .expect("incomplete fresh witness");
        witness.proven_dense_commitment = witness.observed_dense_commitment;
        assert!(witness.validate(&route, &intent, 4, &mut budget()).is_err());
        let (mut omitted, mut route, intent) = fixture();
        let fresh = omitted.paths.last_mut().expect("fresh");
        fresh.has_work = false;
        fresh.vector_reads = 0;
        fresh.discovered = 0;
        fresh.max_vector_reads = 0;
        fresh.max_discovered = 0;
        fresh.work = 2;
        route.vector_reads = 6;
        route.discovered = 6;
        route.tail_vector_reads = 0;
        route.source_coverage_incomplete = true;
        omitted
            .validate(&route, &intent, 4, &mut budget())
            .expect("complete omitted work has no scoring forwards");
    }

    #[test]
    fn zero_scoring_quota_and_oversized_decoder_do_not_claim_complete() {
        let (mut witness, route, intent) = fixture();
        witness.paths[0].max_node_reads = 0;
        witness.paths[0].node_reads = 0;
        assert!(witness.validate(&route, &intent, 4, &mut budget()).is_err());
        let (witness, _, _) = fixture();
        let mut encoded = serde_json::to_value(&witness).expect("protected JSON");
        encoded["selected_ordinals"] = serde_json::json!((1..=65).collect::<Vec<_>>());
        assert!(serde_json::from_value::<HybridSegmentedDenseWitness>(encoded).is_err());
        let mut encoded = serde_json::to_value(&witness).expect("protected JSON");
        encoded["paths"] = serde_json::Value::Array(vec![
            serde_json::to_value(&witness.paths[0])
                .expect("path");
            67
        ]);
        assert!(serde_json::from_value::<HybridSegmentedDenseWitness>(encoded).is_err());
    }
}
