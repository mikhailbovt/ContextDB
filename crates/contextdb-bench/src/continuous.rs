//! Shared synthetic histories and honest accounting for continuous-context comparisons.

use serde::{Deserialize, Serialize};

/// Version of the common history consumed by every continuous-context baseline.
pub const CONTINUOUS_HISTORY_VERSION: &str = "contextdb.continuous-history/v1";

/// An observed message; gold evaluation labels live outside this structure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContinuousEvent {
    /// Stable identity within the synthetic corpus.
    pub id: String,
    /// Independent task scope.
    pub scope: String,
    /// Observed speaker, not a grant of publication authority.
    pub speaker: String,
    /// Query-time availability position.
    pub known_at: u64,
    /// Exact original UTF-8 text.
    pub text: String,
}

/// Evaluation-only target. Never included in reader or router features.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContinuousTarget {
    /// Test identity.
    pub id: String,
    /// Reader question.
    pub query: String,
    /// Task scope supplied by the host.
    pub scope: String,
    /// Latest event available when the question was asked.
    pub known_at: u64,
    /// Required original support set, used by the evaluator only.
    pub evidence_ids: Vec<String>,
    /// Exact answer fragment for the synthetic task.
    pub answer: String,
}

/// Common corpus for rolling, summary/archive/hybrid and owned-runtime comparisons.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContinuousHistory {
    /// Generator version.
    pub version: String,
    /// Original events, ordered by query-time availability.
    pub events: Vec<ContinuousEvent>,
    /// Targets kept separate from query-time content.
    pub evaluation: Vec<ContinuousTarget>,
}

/// Builds a reproducible multilingual correction history without a model call.
#[must_use]
pub fn continuous_history(distractors: u32) -> ContinuousHistory {
    let mut events = Vec::new();
    let mut append = |id: String, scope: &str, speaker: &str, text: String| {
        events.push(ContinuousEvent {
            id,
            scope: scope.into(),
            speaker: speaker.into(),
            known_at: events.len() as u64 + 1,
            text,
        });
    };
    append(
        "atlas-code".into(),
        "atlas",
        "user",
        "Код сейфа Atlas — 7319. Не округлять. 🦉 e\u{301}".into(),
    );
    append(
        "atlas-local".into(),
        "atlas",
        "user",
        "Atlas: облачное хранение запрещено; только локальный диск.".into(),
    );
    append(
        "atlas-proposal".into(),
        "atlas",
        "assistant",
        "Предлагаю рассмотреть cloud backup; разрешения пока нет.".into(),
    );
    for index in 0..distractors {
        append(
            format!("other-{index}"),
            "other",
            "user",
            format!("Other project sample {index}: cloud backup enabled."),
        );
    }
    let before_correction = events.len() as u64;
    events.push(ContinuousEvent {
        id: "atlas-correction".into(),
        scope: "atlas".into(),
        speaker: "user".into(),
        known_at: before_correction + 1,
        text:
            "Исправляю код Atlas: теперь 8426, прежний 7319 отменён. Хранение остаётся локальным."
                .into(),
    });
    ContinuousHistory {
        version: CONTINUOUS_HISTORY_VERSION.into(),
        events,
        evaluation: vec![
            ContinuousTarget {
                id: "rare-detail".into(),
                query: "Какой код Atlas?".into(),
                scope: "atlas".into(),
                known_at: before_correction,
                evidence_ids: vec!["atlas-code".into()],
                answer: "7319".into(),
            },
            ContinuousTarget {
                id: "corrected-detail".into(),
                query: "Какой код Atlas сейчас?".into(),
                scope: "atlas".into(),
                known_at: before_correction + 1,
                evidence_ids: vec!["atlas-correction".into()],
                answer: "8426".into(),
            },
            ContinuousTarget {
                id: "constraint".into(),
                query: "Можно ли хранить Atlas в облаке?".into(),
                scope: "atlas".into(),
                known_at: before_correction,
                evidence_ids: vec!["atlas-local".into()],
                answer: "запрещено".into(),
            },
        ],
    }
}

/// Disjoint billed categories. `None` means unmeasured, never zero.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ContinuousCost {
    /// Uncached input tokens.
    pub uncached_input: Option<u64>,
    /// Cache creation tokens, when billed separately by the provider.
    pub cache_write: Option<u64>,
    /// Cache read tokens.
    pub cache_read: Option<u64>,
    /// Output including billed reasoning, under the selected usage profile.
    pub output: Option<u64>,
    /// Measured reader cost in the experiment's declared currency.
    pub reader_cost: Option<f64>,
    /// Extraction, embedding, router, storage, IO, tools and retries.
    pub auxiliary_cost: Option<f64>,
}

impl ContinuousCost {
    /// Returns a total only when both disjoint cost categories were measured.
    #[must_use]
    pub fn total(&self) -> Option<f64> {
        let reader = self.reader_cost?;
        let auxiliary = self.auxiliary_cost?;
        let total = reader + auxiliary;
        (reader >= 0.0 && auxiliary >= 0.0 && total.is_finite()).then_some(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_cannot_require_future_or_foreign_evidence() {
        let history = continuous_history(1_000);
        for target in &history.evaluation {
            for id in &target.evidence_ids {
                let event = history
                    .events
                    .iter()
                    .find(|event| &event.id == id)
                    .expect("gold event");
                assert!(event.known_at <= target.known_at);
                assert_eq!(event.scope, target.scope);
                assert!(event.text.contains(&target.answer));
            }
        }
        assert_eq!(history, continuous_history(1_000));
    }

    #[test]
    fn missing_and_invalid_costs_are_not_free_calls() {
        let mut cost = ContinuousCost::default();
        assert_eq!(cost.total(), None);
        cost.reader_cost = Some(0.2);
        assert_eq!(cost.total(), None);
        cost.auxiliary_cost = Some(0.3);
        assert_eq!(cost.total(), Some(0.5));
        cost.auxiliary_cost = Some(f64::NAN);
        assert_eq!(cost.total(), None);
        cost.auxiliary_cost = Some(-0.1);
        assert_eq!(cost.total(), None);
    }
}
