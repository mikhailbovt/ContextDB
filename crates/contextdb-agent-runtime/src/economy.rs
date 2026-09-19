//! Measured usage and deterministic residency control. Neither grants authority.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::{RollingPolicy, invalid};
use contextdb_service::ServiceResult;

/// Provider-reported, disjoint billing categories. Unknown is never zero.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderUsage {
    /// Total input, including every cache category below.
    pub input_tokens: Option<u64>,
    /// Input charged at the ordinary input rate, excluding cache creation/reads.
    pub uncached_input_tokens: Option<u64>,
    /// Input charged at a distinct cache-creation rate; zero if not separately billed.
    pub cache_write_tokens: Option<u64>,
    /// Input the endpoint actually reports as reused, not a prefix estimate.
    pub cache_read_tokens: Option<u64>,
    /// All billed output, including any billed hidden reasoning.
    pub output_tokens: Option<u64>,
    /// Subset of output_tokens; never added again to the charge.
    pub reasoning_tokens: Option<u64>,
    /// Endpoint-measured prompt processing time, when available.
    pub prefill_micros: Option<u64>,
}

impl ReaderUsage {
    /// Validate counters without replacing missing categories with zero.
    pub fn validate(&self) -> ServiceResult<()> {
        if let (Some(total), Some(reasoning)) = (self.output_tokens, self.reasoning_tokens)
            && reasoning > total
        {
            return Err(invalid("reasoning exceeds billed output"));
        }
        let parts = [
            self.uncached_input_tokens,
            self.cache_write_tokens,
            self.cache_read_tokens,
        ];
        let known_sum = parts.iter().flatten().try_fold(0_u64, |sum, value| {
            sum.checked_add(*value)
                .ok_or_else(|| invalid("input usage overflows"))
        })?;
        if let Some(total) = self.input_tokens
            && (known_sum > total || (parts.iter().all(Option::is_some) && known_sum != total))
        {
            return Err(invalid(
                "input billing categories overlap or differ from total",
            ));
        }
        Ok(())
    }
}

/// Explicit experiment tariff, never an inferred provider price or a local-free claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderTariff {
    /// Currency/unit label shared by every charge in an aggregate report.
    pub currency: String,
    /// Fixed micro-units per request.
    pub request_micros: u64,
    /// Micro-units per million uncached input tokens.
    pub uncached_per_million_micros: u64,
    /// Micro-units per million separately billed cache-creation tokens.
    pub cache_write_per_million_micros: u64,
    /// Micro-units per million reused input tokens.
    pub cache_read_per_million_micros: u64,
    /// Micro-units per million total output tokens, including reasoning.
    pub output_per_million_micros: u64,
}

impl ReaderTariff {
    /// Round the total variable charge up once. Incomplete or overflowing usage
    /// has no computable price; actual endpoint invoices can be supplied separately.
    pub fn charge_micros(&self, usage: &ReaderUsage) -> Option<u64> {
        usage.validate().ok()?;
        if self.currency.trim().is_empty() || self.currency.len() > 32 {
            return None;
        }
        let mut numerator = 0_u128;
        for (tokens, rate) in [
            (
                usage.uncached_input_tokens?,
                self.uncached_per_million_micros,
            ),
            (
                usage.cache_write_tokens?,
                self.cache_write_per_million_micros,
            ),
            (usage.cache_read_tokens?, self.cache_read_per_million_micros),
            (usage.output_tokens?, self.output_per_million_micros),
        ] {
            numerator = numerator.checked_add(u128::from(tokens) * u128::from(rate))?;
        }
        u64::try_from(
            numerator
                .div_ceil(1_000_000)
                .checked_add(u128::from(self.request_micros))?,
        )
        .ok()
    }
}

/// Optional hysteresis based on the last four actual endpoint observations.
/// Unknown usage resets the cache mode. The hard compiler ceiling still applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheResidencyPolicy {
    /// Higher rotation trigger while measured reuse remains beneficial.
    pub high_tokens: u32,
    /// Enter the sticky mode above this cache-read fraction, in basis points.
    pub enter_hit_bps: u16,
    /// Leave below this fraction; must be smaller than enter_hit_bps.
    pub leave_hit_bps: u16,
    /// Require this many measured calls before adaptation, from two to four.
    pub min_observations: u8,
}
impl CacheResidencyPolicy {
    pub(crate) fn validate(&self, base: RollingPolicy, max_input: u32) -> ServiceResult<()> {
        if self.high_tokens <= base.high_tokens
            || self.high_tokens >= max_input
            || self.enter_hit_bps > 10_000
            || self.leave_hit_bps >= self.enter_hit_bps
            || !(2..=4).contains(&self.min_observations)
        {
            return Err(invalid("invalid measured cache residency policy"));
        }
        Ok(())
    }
}

/// Explain the lifecycle rule without conflating it with content ranking.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidencyReason {
    /// Fixed host thresholds; no adaptive policy configured.
    #[default]
    Fixed,
    /// Insufficient, invalid, or missing actual endpoint observations.
    Unmeasured,
    /// Recent actual cache reuse supports the higher rotation threshold.
    MeasuredReuse,
    /// Recent actual reuse does not meet the configured hysteresis rule.
    MeasuredMiss,
}

/// Deterministic cache controller, isolated from optional evidence utility.
#[derive(Debug, Default)]
pub struct CacheResidencyController {
    samples: VecDeque<(u64, u64)>,
    sticky: bool,
}
impl CacheResidencyController {
    /// Consume actual input/cache-read counts. Missing categories cannot become
    /// cache hits through text overlap, declared support, or tokenizer estimates.
    pub fn observe(&mut self, usage: &ReaderUsage) {
        let measured = usage.validate().is_ok()
            && usage.uncached_input_tokens.is_some()
            && usage.cache_write_tokens.is_some();
        if measured
            && let (Some(total), Some(read)) = (usage.input_tokens, usage.cache_read_tokens)
            && total != 0
        {
            self.samples.push_back((total, read));
            if self.samples.len() > 4 {
                self.samples.pop_front();
            }
        } else {
            self.samples.clear();
            self.sticky = false;
        }
    }

    /// Select only the soft high threshold. Complete-group eviction, mandatory
    /// closure, whole-request bounds and owner admission remain independent.
    pub fn select(
        &mut self,
        base: RollingPolicy,
        adaptive: Option<CacheResidencyPolicy>,
        max_input: u32,
    ) -> ServiceResult<(RollingPolicy, ResidencyReason)> {
        base.validate(max_input)?;
        let Some(policy) = adaptive else {
            self.sticky = false;
            return Ok((base, ResidencyReason::Fixed));
        };
        policy.validate(base, max_input)?;
        if self.samples.len() < usize::from(policy.min_observations) {
            return Ok((base, ResidencyReason::Unmeasured));
        }
        let (total, reads) = self
            .samples
            .iter()
            .fold((0_u128, 0_u128), |(t, r), (a, b)| {
                (t + u128::from(*a), r + u128::from(*b))
            });
        let threshold = if self.sticky {
            policy.leave_hit_bps
        } else {
            policy.enter_hit_bps
        };
        self.sticky = reads * 10_000 >= total * u128::from(threshold);
        if self.sticky {
            Ok((
                RollingPolicy {
                    high_tokens: policy.high_tokens,
                    ..base
                },
                ResidencyReason::MeasuredReuse,
            ))
        } else {
            Ok((base, ResidencyReason::MeasuredMiss))
        }
    }
}
