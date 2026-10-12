//! Explicit embedded-host hybrid discovery; no supplied vector grants execution.

use super::*;
use contextdb_core::ObservationId;

/// Explicit finite segment selection. This limits inspected ordinals per query,
/// not the number of immutable segments that may be retained in the format.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedSegmentLimits {
    /// At most 1..64 directory ordinals inspected in this operation. A bounded
    /// prefix does not establish complete discovery over the whole database.
    pub max_segments: u32,
}

impl OwnedSegmentLimits {
    /// Check the opt-in selection cap; no index or processing grant is created.
    pub fn validate(&self) -> ServiceResult<()> {
        if !(1..=64).contains(&self.max_segments) {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "owned segment selection limit invalid",
                false,
            ));
        }
        Ok(())
    }
}

/// Fixed bounded retrieval settings for an owned per-step query.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedHybridLimits {
    /// Distinct sources retained for preparation, from twenty through one hundred.
    pub sources: u32,
    /// Total base and selected-segment ANN node reads.
    pub node_reads: u32,
    /// Total base, selected-segment and fresh-tail full-vector reads.
    pub vector_reads: u32,
    /// Total base, selected-segment and fresh-tail representation discoveries.
    pub discovered: u32,
    /// Per-cohort beam, bounded by total discovery and at least source limit.
    pub ef_search: u32,
    /// Accepted dense-extension work items, from one through 128.
    pub tail_work: u32,
    /// Permitted fresh vectors, from one through 256, within total vector reads.
    pub tail_vectors: u32,
    /// Optional bounded segmented profile. None preserves the base-plus-tail
    /// encoding and behavior; Some requires separate owner admission and trace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segments: Option<OwnedSegmentLimits>,
}

impl Default for OwnedHybridLimits {
    fn default() -> Self {
        Self {
            sources: 64,
            node_reads: 256,
            vector_reads: 256,
            discovered: 256,
            ef_search: 128,
            tail_work: 128,
            tail_vectors: 256,
            segments: None,
        }
    }
}

impl OwnedHybridLimits {
    /// Validate this finite profile without changing the caller's allowance.
    pub fn validate(&self) -> ServiceResult<()> {
        if let Some(segments) = self.segments {
            segments.validate()?;
        }
        if !(20..=100).contains(&self.sources)
            || [
                self.node_reads,
                self.vector_reads,
                self.discovered,
                self.ef_search,
            ]
            .iter()
            .any(|value| !(1..=4096).contains(value))
            || self.ef_search < self.sources
            || self.ef_search > self.discovered
            || !(1..=128).contains(&self.tail_work)
            || !(1..=256).contains(&self.tail_vectors)
            || self.tail_vectors > self.vector_reads
        {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "owned hybrid retrieval limits invalid",
                false,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_limits_bytes_and_additive_segment_cap_are_distinct() {
        let old = OwnedHybridLimits::default();
        assert_eq!(
            serde_json::to_string(&old).expect("old limits"),
            "{\"sources\":64,\"node_reads\":256,\"vector_reads\":256,\"discovered\":256,\"ef_search\":128,\"tail_work\":128,\"tail_vectors\":256}"
        );
        let mut segmented = old;
        for max_segments in [1, 64] {
            segmented.segments = Some(OwnedSegmentLimits { max_segments });
            segmented.validate().expect("finite opt-in");
            assert_eq!(
                serde_json::from_str::<OwnedHybridLimits>(
                    &serde_json::to_string(&segmented).expect("new limits")
                )
                .expect("new limits round trip"),
                segmented
            );
        }
        for max_segments in [0, 65, u32::MAX] {
            segmented.segments = Some(OwnedSegmentLimits { max_segments });
            assert_eq!(
                segmented.validate().expect_err("selection cap").code,
                ErrorCode::InvalidArgument
            );
        }
        assert!(
            serde_json::from_str::<OwnedSegmentLimits>(
                "{\"max_segments\":1,\"complete_database\":true}"
            )
            .is_err()
        );
    }
}

/// Current owned attempt declaration. The native owner must authenticate it
/// against the exact current checkpoint before any tokenizer or model callback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedHybridIntent {
    /// Pending call in the current accepted owned checkpoint.
    pub call_id: ModelCallId,
    /// Reserved uncaptured model request occurrence for that call.
    pub request_event: ObservationId,
    /// Current incomplete interaction sequence in that checkpoint.
    pub interaction_sequence: u64,
    /// Local bounded prepare attempt, from zero through seven; not a replay lease.
    pub attempt: u8,
    /// Fixed stage-one discovery limits, independent of memory utility scoring.
    pub limits: OwnedHybridLimits,
}

impl OwnedHybridIntent {
    /// Check scalar bounds. This does not authenticate a checkpoint or source.
    pub fn validate(&self) -> ServiceResult<()> {
        self.limits.validate()?;
        if self.attempt >= 8 || self.interaction_sequence == 0 {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "owned hybrid attempt invalid",
                false,
            ));
        }
        Ok(())
    }
}
