use serde::{Deserialize, Serialize};

use crate::{CommitSeq, Validate, ValidationError, ValidationResult};

/// Signed Unix time in microseconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TimestampMicros(pub i64);

/// A half-open valid-time interval. `None` means an unbounded end.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeRange {
    pub start: TimestampMicros,
    pub end: Option<TimestampMicros>,
}

impl TimeRange {
    /// Creates and validates a half-open interval.
    pub fn new(start: TimestampMicros, end: Option<TimestampMicros>) -> ValidationResult<Self> {
        let interval = Self { start, end };
        interval.validate()?;
        Ok(interval)
    }

    /// Creates an interval valid from `start` indefinitely.
    #[must_use]
    pub const fn open_ended(start: TimestampMicros) -> Self {
        Self { start, end: None }
    }

    /// Returns true when two half-open intervals overlap.
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        let self_before_other_end = other.end.is_none_or(|end| self.start < end);
        let other_before_self_end = self.end.is_none_or(|end| other.start < end);
        self_before_other_end && other_before_self_end
    }

    /// Returns true when `instant` is contained in this interval.
    #[must_use]
    pub fn contains(self, instant: TimestampMicros) -> bool {
        instant >= self.start && self.end.is_none_or(|end| instant < end)
    }
}

impl Validate for TimeRange {
    fn validate(&self) -> ValidationResult {
        if let Some(end) = self.end
            && self.start >= end
        {
            return Err(ValidationError::InvalidTimeRange {
                start: self.start.0,
                end: end.0,
            });
        }
        Ok(())
    }
}

/// A half-open transaction-time interval over commit sequences.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRange {
    pub start: CommitSeq,
    pub end: Option<CommitSeq>,
}

impl CommitRange {
    /// Creates and validates a half-open transaction interval.
    pub fn new(start: CommitSeq, end: Option<CommitSeq>) -> ValidationResult<Self> {
        let interval = Self { start, end };
        interval.validate()?;
        Ok(interval)
    }

    /// Creates a transaction interval that is current after `start`.
    #[must_use]
    pub const fn current(start: CommitSeq) -> Self {
        Self { start, end: None }
    }

    /// Returns true when two transaction intervals overlap.
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        let self_before_other_end = other.end.is_none_or(|end| self.start < end);
        let other_before_self_end = self.end.is_none_or(|end| other.start < end);
        self_before_other_end && other_before_self_end
    }

    /// Returns true when a snapshot can see this revision.
    #[must_use]
    pub fn contains(self, commit: CommitSeq) -> bool {
        commit >= self.start && self.end.is_none_or(|end| commit < end)
    }
}

impl Validate for CommitRange {
    fn validate(&self) -> ValidationResult {
        if let Some(end) = self.end
            && self.start >= end
        {
            return Err(ValidationError::InvalidCommitRange {
                start: self.start.get(),
                end: end.get(),
            });
        }
        Ok(())
    }
}

/// Bitemporal validity shared by semantic revisions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitemporalRange {
    pub valid_time: TimeRange,
    pub transaction_time: CommitRange,
}

impl Validate for BitemporalRange {
    fn validate(&self) -> ValidationResult {
        self.valid_time.validate()?;
        self.transaction_time.validate()
    }
}
