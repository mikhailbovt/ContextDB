//! Deterministic logical BENCH-E fixture and evaluator.
//!
//! The fixture exercises identity, selectors, cross-modal references,
//! controlled caption errors, and privacy without decoding media or invoking a
//! model. Its results are logical conformance evidence, never modality-model
//! quality or wall-clock release proof.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::digest::sha256_hex;
use crate::{BENCH_E_FIXTURE_VERSION, BenchError, Result};

/// Logical artifact modality.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    /// Image artifact.
    Image,
    /// Audio artifact.
    Audio,
    /// Document artifact.
    Document,
    /// Derived caption artifact.
    Caption,
}

/// Typed artifact selector with integer portable coordinates.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactSelector {
    /// Whole artifact.
    Whole,
    /// Image rectangle in basis points of width/height.
    ImageRegion {
        /// Left coordinate.
        x_bps: u16,
        /// Top coordinate.
        y_bps: u16,
        /// Width.
        width_bps: u16,
        /// Height.
        height_bps: u16,
    },
    /// Half-open audio span in milliseconds.
    AudioSpan {
        /// Inclusive start.
        start_ms: u32,
        /// Exclusive end.
        end_ms: u32,
    },
    /// Half-open document byte span.
    DocumentRange {
        /// Inclusive start.
        start: u64,
        /// Exclusive end.
        end: u64,
    },
}

impl ArtifactSelector {
    fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::Whole => true,
            Self::ImageRegion {
                x_bps,
                y_bps,
                width_bps,
                height_bps,
            } => {
                *width_bps > 0
                    && *height_bps > 0
                    && u32::from(*x_bps) + u32::from(*width_bps) <= 10_000
                    && u32::from(*y_bps) + u32::from(*height_bps) <= 10_000
            }
            Self::AudioSpan { start_ms, end_ms } => start_ms < end_ms,
            Self::DocumentRange { start, end } => start < end,
        };
        if !valid {
            return Err(BenchError::InvalidConfiguration {
                field: "artifact_selector",
                reason: "selector is empty or outside its artifact".to_owned(),
            });
        }
        Ok(())
    }
}

/// One immutable logical artifact descriptor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalArtifact {
    /// Fixture-local stable ID.
    pub id: String,
    /// Modality.
    pub modality: Modality,
    /// SHA-256 of deterministic synthetic bytes.
    pub content_sha256: String,
    /// Whether retrieval is forbidden to the benchmark principal.
    pub private: bool,
    /// Primary artifact described by this caption.
    pub caption_for: Option<String>,
    /// Controlled semantic claim made by a caption.
    pub caption_claim: Option<String>,
    /// Whether the caption claim is intentionally wrong.
    pub controlled_error: bool,
}

/// Labelled BENCH-E query.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchEQuery {
    /// Stable query ID.
    pub id: String,
    /// Correct artifact, or none for an unknown query.
    pub expected_artifact: Option<String>,
    /// Correct selector, or none for an unknown query.
    pub expected_selector: Option<ArtifactSelector>,
    /// Cross-modal source that must be aligned as evidence.
    pub required_cross_modal_evidence: Option<String>,
    /// Controlled erroneous caption whose claim must not be accepted.
    pub erroneous_caption: Option<String>,
}

/// Deterministic logical multimodal dataset.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchEFixture {
    /// Fixture version.
    pub version: String,
    /// Logical-only boundary marker.
    pub logical_fixture_only: bool,
    /// Immutable artifacts.
    pub artifacts: Vec<LogicalArtifact>,
    /// Labelled queries.
    pub queries: Vec<BenchEQuery>,
}

impl BenchEFixture {
    /// Builds the canonical controlled-error fixture.
    #[must_use]
    pub fn canonical() -> Self {
        let artifact = |id: &str,
                        modality,
                        private,
                        caption_for: Option<&str>,
                        caption_claim: Option<&str>,
                        controlled_error| LogicalArtifact {
            id: id.to_owned(),
            modality,
            content_sha256: sha256_hex(format!("{BENCH_E_FIXTURE_VERSION}:{id}").as_bytes()),
            private,
            caption_for: caption_for.map(str::to_owned),
            caption_claim: caption_claim.map(str::to_owned),
            controlled_error,
        };
        Self {
            version: BENCH_E_FIXTURE_VERSION.to_owned(),
            logical_fixture_only: true,
            artifacts: vec![
                artifact("image-kitchen", Modality::Image, false, None, None, false),
                artifact("audio-note", Modality::Audio, false, None, None, false),
                artifact("document-log", Modality::Document, false, None, None, false),
                artifact(
                    "caption-correct",
                    Modality::Caption,
                    false,
                    Some("image-kitchen"),
                    Some("red cup beside kettle"),
                    false,
                ),
                artifact(
                    "caption-controlled-error",
                    Modality::Caption,
                    false,
                    Some("image-kitchen"),
                    Some("blue cup beside kettle"),
                    true,
                ),
                artifact("image-private", Modality::Image, true, None, None, false),
            ],
            queries: vec![
                BenchEQuery {
                    id: "find-red-cup-region".to_owned(),
                    expected_artifact: Some("image-kitchen".to_owned()),
                    expected_selector: Some(ArtifactSelector::ImageRegion {
                        x_bps: 1_000,
                        y_bps: 2_000,
                        width_bps: 2_500,
                        height_bps: 3_000,
                    }),
                    required_cross_modal_evidence: Some("audio-note".to_owned()),
                    erroneous_caption: Some("caption-controlled-error".to_owned()),
                },
                BenchEQuery {
                    id: "find-spoken-reference".to_owned(),
                    expected_artifact: Some("audio-note".to_owned()),
                    expected_selector: Some(ArtifactSelector::AudioSpan {
                        start_ms: 1_200,
                        end_ms: 2_800,
                    }),
                    required_cross_modal_evidence: Some("image-kitchen".to_owned()),
                    erroneous_caption: Some("caption-controlled-error".to_owned()),
                },
                BenchEQuery {
                    id: "find-document-citation".to_owned(),
                    expected_artifact: Some("document-log".to_owned()),
                    expected_selector: Some(ArtifactSelector::DocumentRange {
                        start: 120,
                        end: 188,
                    }),
                    required_cross_modal_evidence: Some("image-kitchen".to_owned()),
                    erroneous_caption: Some("caption-controlled-error".to_owned()),
                },
                BenchEQuery {
                    id: "unknown-green-vase".to_owned(),
                    expected_artifact: None,
                    expected_selector: None,
                    required_cross_modal_evidence: None,
                    erroneous_caption: None,
                },
            ],
        }
    }

    /// Validates IDs, selectors, references, and controlled-error coverage.
    pub fn validate(&self) -> Result<()> {
        if self.version != BENCH_E_FIXTURE_VERSION || !self.logical_fixture_only {
            return invalid(
                "bench_e.version",
                "fixture must retain its logical-only marker",
            );
        }
        let artifacts: BTreeMap<_, _> = self
            .artifacts
            .iter()
            .map(|artifact| (artifact.id.as_str(), artifact))
            .collect();
        if artifacts.len() != self.artifacts.len() || self.queries.is_empty() {
            return invalid(
                "bench_e.artifacts",
                "artifact IDs must be unique and queries nonempty",
            );
        }
        if !self.artifacts.iter().any(|artifact| artifact.private)
            || !self
                .artifacts
                .iter()
                .any(|artifact| artifact.controlled_error)
        {
            return invalid(
                "bench_e.coverage",
                "private and controlled-error artifacts are mandatory",
            );
        }
        let mut query_ids = BTreeSet::new();
        for query in &self.queries {
            if !query_ids.insert(query.id.as_str()) {
                return invalid("bench_e.queries", "query IDs must be unique");
            }
            if let Some(selector) = &query.expected_selector {
                selector.validate()?;
            }
            for reference in [
                query.expected_artifact.as_deref(),
                query.required_cross_modal_evidence.as_deref(),
                query.erroneous_caption.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                if !artifacts.contains_key(reference) {
                    return invalid(
                        "bench_e.query_reference",
                        "query references unknown artifact",
                    );
                }
            }
            if query.expected_artifact.is_some() != query.expected_selector.is_some() {
                return invalid(
                    "bench_e.expected_selector",
                    "artifact and selector must both be present or absent",
                );
            }
        }
        Ok(())
    }

    /// SHA-256 of the canonical fixture.
    pub fn digest(&self) -> Result<String> {
        Ok(sha256_hex(&serde_json::to_vec(self)?))
    }

    /// Perfect deterministic proposal used only to validate evaluator wiring.
    #[must_use]
    pub fn oracle_candidates(&self) -> Vec<BenchECandidate> {
        self.queries
            .iter()
            .map(|query| BenchECandidate {
                query_id: query.id.clone(),
                artifact_id: query.expected_artifact.clone(),
                selector: query.expected_selector.clone(),
                evidence_artifact_ids: query
                    .required_cross_modal_evidence
                    .iter()
                    .cloned()
                    .collect(),
                accepted_caption_claims: BTreeSet::new(),
            })
            .collect()
    }
}

/// Provider-neutral validated candidate output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchECandidate {
    /// Query being answered.
    pub query_id: String,
    /// Selected artifact, or none for unknown.
    pub artifact_id: Option<String>,
    /// Typed selector.
    pub selector: Option<ArtifactSelector>,
    /// Evidence artifacts aligned to the answer.
    pub evidence_artifact_ids: BTreeSet<String>,
    /// Caption claims accepted as true by the candidate.
    pub accepted_caption_claims: BTreeSet<String>,
}

/// BENCH-E integer thresholds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchEThresholds {
    /// Minimum correct artifact identity.
    pub minimum_artifact_identity_bps: u16,
    /// Minimum exact selector accuracy.
    pub minimum_selector_accuracy_bps: u16,
    /// Minimum cross-modal evidence alignment.
    pub minimum_cross_modal_retrieval_bps: u16,
    /// Minimum containment of controlled caption errors.
    pub minimum_caption_error_containment_bps: u16,
}

impl Default for BenchEThresholds {
    fn default() -> Self {
        Self {
            minimum_artifact_identity_bps: 9_500,
            minimum_selector_accuracy_bps: 9_500,
            minimum_cross_modal_retrieval_bps: 9_000,
            minimum_caption_error_containment_bps: 10_000,
        }
    }
}

/// Logical BENCH-E scorecard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchEReport {
    /// Fixture identity.
    pub fixture_sha256: String,
    /// Always true: no media decoding/model quality was measured.
    pub logical_fixture_only: bool,
    /// Correct artifact selections, including correct unknowns.
    pub artifact_identity_bps: u16,
    /// Exact typed selector matches.
    pub selector_accuracy_bps: u16,
    /// Required cross-modal evidence aligned.
    pub cross_modal_retrieval_bps: u16,
    /// Controlled erroneous caption claims rejected.
    pub caption_error_containment_bps: u16,
    /// Forbidden private artifacts selected or cited.
    pub privacy_leak_count: u64,
    /// Evidence IDs not present in the immutable fixture.
    pub hallucinated_evidence_count: u64,
    /// True only when every quality threshold and exact privacy/evidence gate passes.
    pub passed: bool,
}

/// Evaluates provider-neutral candidates against immutable ground truth.
pub fn evaluate_bench_e(
    fixture: &BenchEFixture,
    candidates: &[BenchECandidate],
    thresholds: BenchEThresholds,
) -> Result<BenchEReport> {
    fixture.validate()?;
    for value in [
        thresholds.minimum_artifact_identity_bps,
        thresholds.minimum_selector_accuracy_bps,
        thresholds.minimum_cross_modal_retrieval_bps,
        thresholds.minimum_caption_error_containment_bps,
    ] {
        if value > 10_000 {
            return invalid("bench_e.threshold", "basis points cannot exceed 10000");
        }
    }
    let artifacts: BTreeMap<_, _> = fixture
        .artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect();
    let candidates_by_query: BTreeMap<_, _> = candidates
        .iter()
        .map(|candidate| (candidate.query_id.as_str(), candidate))
        .collect();
    if candidates_by_query.len() != candidates.len()
        || candidates_by_query.len() != fixture.queries.len()
        || fixture
            .queries
            .iter()
            .any(|query| !candidates_by_query.contains_key(query.id.as_str()))
    {
        return invalid(
            "bench_e.candidates",
            "exactly one candidate is required for every fixture query",
        );
    }

    let mut identity_hits = 0_u64;
    let mut selector_hits = 0_u64;
    let mut selector_total = 0_u64;
    let mut cross_modal_hits = 0_u64;
    let mut cross_modal_total = 0_u64;
    let mut containment_hits = 0_u64;
    let mut containment_total = 0_u64;
    let mut privacy_leaks = 0_u64;
    let mut hallucinated = 0_u64;

    for query in &fixture.queries {
        let candidate = candidates_by_query
            .get(query.id.as_str())
            .copied()
            .ok_or_else(|| {
                BenchError::Integrity("candidate disappeared during scoring".to_owned())
            })?;
        if candidate.artifact_id == query.expected_artifact {
            identity_hits = identity_hits.saturating_add(1);
        }
        if query.expected_selector.is_some() {
            selector_total = selector_total.saturating_add(1);
            if candidate.selector == query.expected_selector {
                selector_hits = selector_hits.saturating_add(1);
            }
        }
        if let Some(required) = &query.required_cross_modal_evidence {
            cross_modal_total = cross_modal_total.saturating_add(1);
            if candidate.evidence_artifact_ids.contains(required) {
                cross_modal_hits = cross_modal_hits.saturating_add(1);
            }
        }
        if let Some(erroneous_id) = &query.erroneous_caption {
            containment_total = containment_total.saturating_add(1);
            let erroneous_claim = artifacts
                .get(erroneous_id.as_str())
                .and_then(|artifact| artifact.caption_claim.as_ref());
            if erroneous_claim
                .is_none_or(|claim| !candidate.accepted_caption_claims.contains(claim))
            {
                containment_hits = containment_hits.saturating_add(1);
            }
        }
        for artifact_id in candidate
            .artifact_id
            .iter()
            .chain(candidate.evidence_artifact_ids.iter())
        {
            match artifacts.get(artifact_id.as_str()) {
                Some(artifact) if artifact.private => {
                    privacy_leaks = privacy_leaks.saturating_add(1);
                }
                Some(_) => {}
                None => {
                    hallucinated = hallucinated.saturating_add(1);
                }
            }
        }
    }

    let query_total = u64::try_from(fixture.queries.len())
        .map_err(|_| BenchError::ArithmeticOverflow("BENCH-E query count"))?;
    let artifact_identity_bps = basis_points(identity_hits, query_total);
    let selector_accuracy_bps = basis_points(selector_hits, selector_total);
    let cross_modal_retrieval_bps = basis_points(cross_modal_hits, cross_modal_total);
    let caption_error_containment_bps = basis_points(containment_hits, containment_total);
    let passed = artifact_identity_bps >= thresholds.minimum_artifact_identity_bps
        && selector_accuracy_bps >= thresholds.minimum_selector_accuracy_bps
        && cross_modal_retrieval_bps >= thresholds.minimum_cross_modal_retrieval_bps
        && caption_error_containment_bps >= thresholds.minimum_caption_error_containment_bps
        && privacy_leaks == 0
        && hallucinated == 0;
    Ok(BenchEReport {
        fixture_sha256: fixture.digest()?,
        logical_fixture_only: true,
        artifact_identity_bps,
        selector_accuracy_bps,
        cross_modal_retrieval_bps,
        caption_error_containment_bps,
        privacy_leak_count: privacy_leaks,
        hallucinated_evidence_count: hallucinated,
        passed,
    })
}

fn basis_points(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 10_000;
    }
    let value = u128::from(numerator).saturating_mul(10_000) / u128::from(denominator);
    u16::try_from(value).unwrap_or(10_000)
}

fn invalid<T>(field: &'static str, reason: &'static str) -> Result<T> {
    Err(BenchError::InvalidConfiguration {
        field,
        reason: reason.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "BENCH-E evaluator tests use immediate failure semantics"
    )]

    use super::{BenchEFixture, BenchEThresholds, evaluate_bench_e};

    #[test]
    fn oracle_validates_logical_evaluator_only() {
        let fixture = BenchEFixture::canonical();
        let report = evaluate_bench_e(
            &fixture,
            &fixture.oracle_candidates(),
            BenchEThresholds::default(),
        )
        .expect("evaluate");
        assert!(report.passed);
        assert!(report.logical_fixture_only);
    }

    #[test]
    fn private_and_hallucinated_evidence_fail_exact_gates() {
        let fixture = BenchEFixture::canonical();
        let mut candidates = fixture.oracle_candidates();
        candidates[0]
            .evidence_artifact_ids
            .insert("image-private".to_owned());
        candidates[1]
            .evidence_artifact_ids
            .insert("artifact-that-does-not-exist".to_owned());
        let report =
            evaluate_bench_e(&fixture, &candidates, BenchEThresholds::default()).expect("evaluate");
        assert!(!report.passed);
        assert_eq!(report.privacy_leak_count, 1);
        assert_eq!(report.hallucinated_evidence_count, 1);
    }

    #[test]
    fn controlled_caption_error_cannot_override_primary_evidence() {
        let fixture = BenchEFixture::canonical();
        let mut candidates = fixture.oracle_candidates();
        candidates[0]
            .accepted_caption_claims
            .insert("blue cup beside kettle".to_owned());
        let report =
            evaluate_bench_e(&fixture, &candidates, BenchEThresholds::default()).expect("evaluate");
        assert!(!report.passed);
        assert!(report.caption_error_containment_bps < 10_000);
    }
}
