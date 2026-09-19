//! Bounded process-local measurements. Export/drain explicitly for run reports.

use std::{collections::VecDeque, time::Instant};

use contextdb_core::{AgentRunId, ModelCallId, ModelRequestManifest, RequestPart};
use contextdb_service::ErrorCode;
use serde::{Deserialize, Serialize};

use crate::{ReaderUsage, ResidencyReason};

/// One call to step, including prepare retries and rejected/unknown outcomes.
/// Contains no source text, questions, replies, source IDs or wire hashes.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepMeasurement {
    /// Run identity for joining measurements to host-authorized run records.
    pub run: Option<AgentRunId>,
    /// Exact attempt identity; absent if rejected before planning a call.
    pub call: Option<ModelCallId>,
    /// Monotonic local wall duration of the complete step, including failures.
    pub elapsed_micros: u64,
    /// Bounded rotation/tokenization work, excluding the reader call.
    pub rotation_micros: u64,
    /// Interpretation/index hook work, excluding context compilation.
    pub preparation_hook_micros: u64,
    /// All prepare attempts, including unsuccessful ones.
    pub prepare_micros: u64,
    /// Number of actual compiler invocations.
    pub prepare_attempts: u32,
    /// Scorer-only time when every prepare attempt returned measurements.
    /// Failed compiler attempts make this unknown, not free.
    pub scorer_micros: Option<u64>,
    /// Removed complete interaction groups, including budget-driven retries.
    pub evicted_groups: u32,
    /// Lifecycle rule chosen before compilation; never the content scorer.
    pub residency_reason: ResidencyReason,
    /// Selected soft rotation trigger.
    pub rotation_high_tokens: u32,
    /// Actual provider dispatch happened, even if no result was returned.
    pub dispatched: bool,
    /// Provider-call wall duration; not a billed cache/prefill estimate.
    pub reader_micros: Option<u64>,
    /// Endpoint-reported usage. None categories include failed calls with no usage.
    pub usage: ReaderUsage,
    /// Invalid adapter counters were discarded; they cannot enter an aggregate.
    pub invalid_usage: bool,
    /// Whole wire sent to the adapter, including its protocol/options.
    pub wire_bytes: Option<u64>,
    /// Replayed original bytes in this request, after declared source transforms.
    pub source_echo_bytes: Option<u64>,
    /// Novel protocol/control bytes stored by the capture manifest.
    pub novel_bytes: Option<u64>,
    /// Common 256-byte prefix chunks of consecutive transmitted wires. A lower
    /// bound on byte similarity only; never represented as a cache hit.
    pub matching_prefix_floor_bytes: Option<u64>,
    /// Shared logical work allowance consumed, not physical storage IOPS.
    pub work_units: u64,
    /// Shared logical byte allowance consumed, not physical disk traffic.
    pub charged_bytes: u64,
    /// Final error, including persistence errors after a successful provider call.
    pub error: Option<ErrorCode>,
    /// Runtime requires provider outcome reconciliation before another dispatch.
    pub outcome_unknown: bool,
}

/// A drained observation window. This is not a durable billing ledger.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeMeasurements {
    /// Every retained step, including failed/rejected attempts.
    pub steps: Vec<StepMeasurement>,
    /// Cumulative overwritten measurements. Any nonzero value makes this runtime
    /// window insufficient to claim complete run cost.
    pub dropped_steps: u64,
    /// Resume does not invent measurements for work before this process.
    pub prior_process_unmeasured: bool,
}

#[derive(Debug, Default)]
pub(crate) struct Telemetry {
    steps: VecDeque<StepMeasurement>,
    dropped: u64,
    prior_process: bool,
    previous_wire: Option<Vec<(blake3::Hash, usize)>>,
}
impl Telemetry {
    pub(crate) fn resumed() -> Self {
        Self {
            prior_process: true,
            ..Self::default()
        }
    }
    pub(crate) fn push(&mut self, measurement: StepMeasurement) {
        if self.steps.len() == 64 {
            self.steps.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.steps.push_back(measurement);
    }
    pub(crate) fn drain(&mut self) -> RuntimeMeasurements {
        RuntimeMeasurements {
            steps: self.steps.drain(..).collect(),
            dropped_steps: self.dropped,
            prior_process_unmeasured: self.prior_process,
        }
    }
    pub(crate) fn wire(&mut self, wire: &[u8], measurement: &mut StepMeasurement) {
        let chunks = wire
            .chunks(256)
            .map(|chunk| (blake3::hash(chunk), chunk.len()))
            .collect::<Vec<_>>();
        measurement.matching_prefix_floor_bytes = self.previous_wire.as_ref().map(|previous| {
            chunks
                .iter()
                .zip(previous)
                .take_while(|(a, b)| a == b)
                .map(|(a, _)| a.1 as u64)
                .sum()
        });
        self.previous_wire = Some(chunks);
        measurement.wire_bytes = Some(wire.len() as u64);
    }
}

pub(crate) fn manifest_counts(manifest: &ModelRequestManifest, measurement: &mut StepMeasurement) {
    let mut echo = 0_u64;
    for part in &manifest.parts {
        echo += match part {
            RequestPart::Source { span } => span.end - span.start,
            RequestPart::JsonStringSource { byte_length, .. } => *byte_length,
            _ => 0,
        };
    }
    measurement.source_echo_bytes = Some(echo);
    measurement.novel_bytes = manifest.byte_length.checked_sub(echo);
}

pub(crate) fn elapsed(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}
