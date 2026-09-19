//! Incremental provider boundary alongside the materialized-corpus oracle.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use contextdb_core::{ObservationId, OriginalSourceSpan, RawFilter, RawSource, RawTextQuery};
use serde::{Deserialize, Serialize};

/// Cooperative cancellation shared with the caller's whole prepare operation.
#[derive(Clone, Debug, Default)]
pub struct QueryCancellation(Arc<AtomicBool>);

impl QueryCancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryLimit {
    Work,
    Bytes,
    Deadline,
    Cancelled,
}

/// One shared allowance from authorization through final materialization.
#[derive(Debug)]
pub struct QueryBudget {
    deadline: Instant,
    cancellation: QueryCancellation,
    remaining_work: u64,
    remaining_bytes: u64,
}

impl QueryBudget {
    pub fn new(work: u64, bytes: u64, timeout: Duration, cancellation: QueryCancellation) -> Self {
        let now = Instant::now();
        Self {
            deadline: now.checked_add(timeout).unwrap_or(now),
            cancellation,
            remaining_work: work,
            remaining_bytes: bytes,
        }
    }

    pub fn check(&self) -> Result<(), QueryLimit> {
        if self.cancellation.is_cancelled() {
            return Err(QueryLimit::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(QueryLimit::Deadline);
        }
        Ok(())
    }

    pub fn charge(&mut self, work: u64, bytes: u64) -> Result<(), QueryLimit> {
        self.check()?;
        if work > self.remaining_work {
            return Err(QueryLimit::Work);
        }
        if bytes > self.remaining_bytes {
            return Err(QueryLimit::Bytes);
        }
        self.remaining_work -= work;
        self.remaining_bytes -= bytes;
        Ok(())
    }

    pub fn remaining_work(&self) -> u64 {
        self.remaining_work
    }
    pub fn remaining_bytes(&self) -> u64 {
        self.remaining_bytes
    }
}

/// Retrieval intent distinguishes an exhaustive cursor from a ranked candidate set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum IndexedSelection {
    /// Stable enumeration; every page shares a logical generation/view binding.
    Exhaustive {
        page_size: u32,
        continuation: Option<String>,
    },
    /// Bounded candidates ranked without statistics from other policy domains.
    TopK { limit: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexedQuery {
    pub filter: RawFilter,
    pub text: Option<RawTextQuery>,
    /// Optional direct outgoing/incoming causal adjacency, not a graph-wide scan.
    pub neighbor_of: Option<ObservationId>,
    pub selection: IndexedSelection,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexedHit {
    pub source: RawSource,
    pub matches: Vec<OriginalSourceSpan>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexedCompletion {
    Complete,
    More,
    WorkLimit,
    ByteLimit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexedPage {
    pub hits: Vec<IndexedHit>,
    pub completion: IndexedCompletion,
    pub continuation: Option<String>,
    /// Opaque logical/generation binding, with no global archive counters.
    pub snapshot: String,
}

/// Authorization establishes an opaque view before any content-search route.
/// Views must be short lived and checked again before disclosure or effects.
pub trait IndexedRecallProvider {
    type View;
    type Error;

    fn open_view(
        &self,
        known_at: Option<u64>,
        budget: &mut QueryBudget,
    ) -> Result<Self::View, Self::Error>;
    fn candidates(
        &self,
        view: &Self::View,
        query: &IndexedQuery,
        budget: &mut QueryBudget,
    ) -> Result<IndexedPage, Self::Error>;
}
