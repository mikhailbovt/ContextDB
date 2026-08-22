use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use contextdb_core::ContentDigest;

use crate::types::{canonical_digest, validate_text};
use crate::{ModelCallRequest, ModelRuntimeError, Result};

/// Scheduler urgency class. Urgent durable-write projections are drained before
/// interactive, background, and maintenance work.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BatchPriority {
    /// Explicit high-priority memory write.
    Urgent,
    /// Interactive request.
    Interactive,
    /// Normal asynchronous projection.
    Background,
    /// Low-priority consolidation/reflection maintenance.
    Maintenance,
}

/// Stable process-local scheduled-job identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BatchJobId(u64);

impl BatchJobId {
    /// Returns the process-local sequence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Optional caller key used to coalesce superseded summary/rebuild work.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CoalesceKey(String);

impl CoalesceKey {
    /// Creates a bounded coalescing identity.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "batch.coalesce_key", 512)?;
        Ok(Self(value))
    }
}

/// Caller-supplied compatibility partition such as vector-space ID or tenant
/// processing shard. Native batches never cross this boundary.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
pub struct BatchPartition(String);

impl BatchPartition {
    /// Creates a bounded batch partition.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "batch.partition", 512)?;
        Ok(Self(value))
    }
}

/// One queued request.
#[derive(Clone, Debug)]
pub struct ScheduledModelCall {
    /// Scheduler identity.
    pub id: BatchJobId,
    /// Priority.
    pub priority: BatchPriority,
    /// Provider-neutral gateway request.
    pub request: ModelCallRequest,
    /// Optional replacement/coalescing key.
    pub coalesce_key: Option<CoalesceKey>,
    /// Optional vector-space/tenant/domain compatibility partition.
    pub partition: Option<BatchPartition>,
}

/// One compatible batch in deterministic priority/FIFO order.
#[derive(Clone, Debug)]
pub struct ScheduledBatch {
    /// Payload-free compatibility digest.
    pub compatibility_digest: ContentDigest,
    /// Ordered unique jobs.
    pub jobs: Vec<ScheduledModelCall>,
}

/// Enqueue behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnqueueDisposition {
    /// New job inserted.
    Inserted,
    /// Identical pending request already exists.
    Deduplicated,
    /// Older coalescible work was superseded.
    Coalesced {
        /// Removed job.
        replaced: BatchJobId,
    },
}

/// Enqueue receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnqueueReceipt {
    /// Active job identity.
    pub job_id: BatchJobId,
    /// Insert/dedup/coalescing result.
    pub disposition: EnqueueDisposition,
}

/// Hard scheduler bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchSchedulerConfig {
    /// Maximum pending jobs before backpressure.
    pub max_pending: usize,
    /// Maximum jobs in one compatible batch.
    pub max_batch_size: usize,
}

impl Default for BatchSchedulerConfig {
    fn default() -> Self {
        Self {
            max_pending: 10_000,
            max_batch_size: 64,
        }
    }
}

impl BatchSchedulerConfig {
    fn validate(self) -> Result<()> {
        if self.max_pending == 0
            || self.max_batch_size == 0
            || self.max_batch_size > self.max_pending
        {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "batch_scheduler",
                reason: "invalid queue or batch bound",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CompatibilityKey {
    digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DedupKey {
    compatibility: CompatibilityKey,
    input_digest: ContentDigest,
}

#[derive(Clone, Debug)]
struct PendingJob {
    call: ScheduledModelCall,
    compatibility: CompatibilityKey,
    dedup: DedupKey,
    sequence: u64,
}

#[derive(Debug, Default)]
struct SchedulerState {
    next_id: u64,
    jobs: BTreeMap<BatchJobId, PendingJob>,
    dedup: BTreeMap<DedupKey, BatchJobId>,
    coalescing: BTreeMap<(CompatibilityKey, CoalesceKey), BatchJobId>,
}

/// Bounded deterministic scheduler for compatible model calls.
pub struct BatchScheduler {
    config: BatchSchedulerConfig,
    state: Mutex<SchedulerState>,
}

impl fmt::Debug for BatchScheduler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchScheduler")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl BatchScheduler {
    /// Creates an empty bounded scheduler.
    pub fn new(config: BatchSchedulerConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            state: Mutex::new(SchedulerState::default()),
        })
    }

    /// Enqueues, deduplicates identical digests, or coalesces superseded work.
    pub fn enqueue(
        &self,
        request: ModelCallRequest,
        priority: BatchPriority,
        coalesce_key: Option<CoalesceKey>,
    ) -> Result<EnqueueReceipt> {
        self.enqueue_partitioned(request, priority, coalesce_key, None)
    }

    /// Enqueues with an explicit vector-space/tenant/domain compatibility
    /// partition.
    pub fn enqueue_partitioned(
        &self,
        request: ModelCallRequest,
        priority: BatchPriority,
        coalesce_key: Option<CoalesceKey>,
        partition: Option<BatchPartition>,
    ) -> Result<EnqueueReceipt> {
        let compatibility = compatibility_key(&request, partition.as_ref())?;
        let dedup = DedupKey {
            compatibility: compatibility.clone(),
            input_digest: request.input.dedup_digest()?,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        if let Some(existing) = state.dedup.get(&dedup).copied() {
            if let Some(job) = state.jobs.get_mut(&existing)
                && priority_rank(priority) < priority_rank(job.call.priority)
            {
                job.call.priority = priority;
            }
            return Ok(EnqueueReceipt {
                job_id: existing,
                disposition: EnqueueDisposition::Deduplicated,
            });
        }
        let replaced = coalesce_key.as_ref().and_then(|key| {
            state
                .coalescing
                .get(&(compatibility.clone(), key.clone()))
                .copied()
        });
        if replaced.is_none() && state.jobs.len() >= self.config.max_pending {
            return Err(ModelRuntimeError::BatchCapacity);
        }
        if let Some(replaced) = replaced {
            remove_job(&mut state, replaced);
        }
        state.next_id = state
            .next_id
            .checked_add(1)
            .ok_or(ModelRuntimeError::ArithmeticOverflow)?;
        let id = BatchJobId(state.next_id);
        let call = ScheduledModelCall {
            id,
            priority,
            request,
            coalesce_key: coalesce_key.clone(),
            partition,
        };
        state.dedup.insert(dedup.clone(), id);
        if let Some(key) = coalesce_key {
            state.coalescing.insert((compatibility.clone(), key), id);
        }
        state.jobs.insert(
            id,
            PendingJob {
                call,
                compatibility,
                dedup,
                sequence: id.get(),
            },
        );
        Ok(EnqueueReceipt {
            job_id: id,
            disposition: replaced.map_or(EnqueueDisposition::Inserted, |replaced| {
                EnqueueDisposition::Coalesced { replaced }
            }),
        })
    }

    /// Drains a bounded number of compatible batches. Jobs are unique and
    /// urgent-first; FIFO is stable within one priority.
    pub fn drain(&self, max_batches: usize) -> Result<Vec<ScheduledBatch>> {
        if max_batches == 0 {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "batch_scheduler.max_batches",
                reason: "must be positive",
            });
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        let mut batches = Vec::new();
        while !state.jobs.is_empty() && batches.len() < max_batches {
            let mut ordered: Vec<_> = state
                .jobs
                .values()
                .map(|job| (job.call.priority, job.sequence, job.call.id))
                .collect();
            ordered.sort_by(|left, right| {
                priority_rank(left.0)
                    .cmp(&priority_rank(right.0))
                    .then_with(|| left.1.cmp(&right.1))
            });
            let Some((first_priority, _, first_id)) = ordered.first().copied() else {
                break;
            };
            let compatibility = state
                .jobs
                .get(&first_id)
                .map(|job| job.compatibility.clone())
                .ok_or(ModelRuntimeError::LockPoisoned)?;
            let ids: Vec<_> = ordered
                .into_iter()
                .map(|(_, _, id)| id)
                .filter(|id| {
                    state.jobs.get(id).is_some_and(|job| {
                        job.compatibility == compatibility && job.call.priority == first_priority
                    })
                })
                .take(self.config.max_batch_size)
                .collect();
            let mut jobs = Vec::with_capacity(ids.len());
            for id in ids {
                if let Some(job) = remove_job(&mut state, id) {
                    jobs.push(job.call);
                }
            }
            if !jobs.is_empty() {
                batches.push(ScheduledBatch {
                    compatibility_digest: compatibility.digest,
                    jobs,
                });
            }
        }
        Ok(batches)
    }

    /// Current pending count.
    pub fn pending_len(&self) -> Result<usize> {
        Ok(self
            .state
            .lock()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?
            .jobs
            .len())
    }
}

fn compatibility_key(
    request: &ModelCallRequest,
    partition: Option<&BatchPartition>,
) -> Result<CompatibilityKey> {
    let policy_digest = request.routing_policy.digest()?;
    let digest = canonical_digest(
        b"contextdb-model-batch-compatibility-v1\0",
        &(
            &request.capability,
            &request.prompt,
            &request.output_schema,
            request.input.modality,
            request.input.sensitivity,
            &request.input.language,
            request.input.input_tokens,
            request.max_output_tokens,
            request.allow_deterministic_fallback,
            policy_digest,
            partition,
        ),
    )?;
    Ok(CompatibilityKey { digest })
}

fn remove_job(state: &mut SchedulerState, id: BatchJobId) -> Option<PendingJob> {
    let job = state.jobs.remove(&id)?;
    state.dedup.remove(&job.dedup);
    if let Some(key) = &job.call.coalesce_key {
        state
            .coalescing
            .remove(&(job.compatibility.clone(), key.clone()));
    }
    Some(job)
}

const fn priority_rank(priority: BatchPriority) -> u8 {
    match priority {
        BatchPriority::Urgent => 0,
        BatchPriority::Interactive => 1,
        BatchPriority::Background => 2,
        BatchPriority::Maintenance => 3,
    }
}
