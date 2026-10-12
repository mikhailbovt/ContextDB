//! Explicit embedded-host hybrid discovery; no supplied vector grants execution.

use super::*;
use contextdb_core::ObservationId;

/// Fixed bounded retrieval settings for an owned per-step query.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedHybridLimits {
    /// Distinct sources retained for preparation, from twenty through one hundred.
    pub sources: u32,
    /// Total immutable-base ANN node reads.
    pub node_reads: u32,
    /// Total base plus tail full-vector reads.
    pub vector_reads: u32,
    /// Total base plus tail admitted representation discoveries.
    pub discovered: u32,
    /// Per-cohort beam, bounded by total discovery and at least source limit.
    pub ef_search: u32,
    /// Accepted dense-extension work items, from one through 128.
    pub tail_work: u32,
    /// Permitted fresh vectors, from one through 256, within total vector reads.
    pub tail_vectors: u32,
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
        }
    }
}

impl OwnedHybridLimits {
    /// Validate this finite profile without changing the caller's allowance.
    pub fn validate(&self) -> ServiceResult<()> {
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
