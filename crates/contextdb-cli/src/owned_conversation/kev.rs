//! Explicit development scorer. The native owner supplies current source admission.

use std::{
    sync::{Mutex, MutexGuard, TryLockError},
    thread,
    time::{Duration, Instant},
};

use contextdb_context::{
    ContextError, ContextScorer, Result, ScorerFailurePolicy, ScoringUnit, SemanticScoringProfile,
    SemanticScoringUnit,
};
use contextdb_recall::QueryBudget;
use contextdb_service::{ErrorCode, ServiceError};
use serde::{Deserialize, Serialize};

use crate::CliResult;

mod config;
mod transport;
pub(super) use config::{KevConfig, PolicyBinding};
use config::{MAX_META, SourcePins, sha256};
use transport::Process;

const FORMAT: &str = "contextdb.kev-worker.rendered-closure.v1";
const PROFILE: &str = "contextdb.kev-public-synthetic-rendered-closure-bce.v1";
const PROJECTION: &str = "contextdb.kev-rendered-closure-projection.v1";
const SCORER: &str = "contextdb.kev-development.rendered-closure.v1";

enum State {
    Cold,
    Live(Process),
    Closed,
}

pub(super) struct KevScorer {
    config: KevConfig,
    config_digest: String,
    revision: String,
    state: Mutex<State>,
    next_id: Mutex<u64>,
}

impl std::fmt::Debug for KevScorer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KevScorer")
            .field("profile", &PROFILE)
            .field("limits", &self.config.limits)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    format: String,
    operation: String,
    status: String,
    config_sha256: String,
    bundle_sha256: String,
    worker_sha256: String,
    model_profile_sha256: String,
    profile: String,
    projection: String,
    feature_format: String,
    tensor_sha256: String,
    source_sha256: SourcePins,
    quality: String,
}

#[derive(Serialize)]
struct ScoreRequest<'a> {
    format: &'static str,
    operation: &'static str,
    id: u64,
    config_sha256: &'a str,
    input_bytes: usize,
    input_sha256: &'a str,
    timeout_micros: u64,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum ScoreReply {
    Ok {
        format: String,
        operation: String,
        id: u64,
        config_sha256: String,
        input_sha256: String,
        yes_minus_no: f64,
    },
    Error {
        format: String,
        operation: String,
        id: u64,
        config_sha256: String,
        input_sha256: String,
        code: ReplyCode,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReplyCode {
    ProjectionRefused,
    TokenRefused,
    DeadlineRefused,
    ResourceRefused,
    InferenceRefused,
    NonfiniteScore,
}

impl KevScorer {
    pub(super) fn new(config: &KevConfig) -> CliResult<Self> {
        config.validate()?;
        let digest = config.digest()?;
        Ok(Self {
            config: config.clone(),
            revision: format!("{SCORER}/{digest}"),
            config_digest: digest,
            state: Mutex::new(State::Cold),
            next_id: Mutex::new(1),
        })
    }

    /// Warm only after the host has admitted the durable owner/config binding.
    /// This separate startup deadline never extends a preparation allowance.
    pub(super) fn warm(&self) -> CliResult<()> {
        let deadline =
            Instant::now() + Duration::from_micros(self.config.limits.startup_timeout_micros);
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| error("worker warm state refused"))?;
        if !matches!(*state, State::Cold) {
            return Err(error("worker already warmed or closed").into());
        }
        *state = State::Closed;
        self.config.verify_files()?;
        if Instant::now() >= deadline {
            return Err(error("worker startup deadline exceeded").into());
        }
        let (process, ready) =
            Process::spawn(&self.config, &self.config_digest).map_err(context_error)?;
        let bytes = transport::wait(&ready, deadline, None).map_err(context_error)?;
        self.validate_ready(&bytes).map_err(context_error)?;
        if Instant::now() >= deadline {
            return Err(error("worker startup deadline exceeded").into());
        }
        *state = State::Live(process);
        Ok(())
    }

    fn validate_ready(&self, bytes: &[u8]) -> Result<()> {
        let ready: Ready =
            serde_json::from_slice(bytes).map_err(|_| refused("worker READY invalid"))?;
        if ready.format != FORMAT
            || ready.operation != "ready"
            || ready.status != "ready"
            || ready.config_sha256 != self.config_digest
            || ready.bundle_sha256 != self.config.bundle_sha256
            || ready.worker_sha256 != self.config.worker_sha256
            || ready.model_profile_sha256 != self.config.model_profile_sha256
            || ready.tensor_sha256 != self.config.tensor_sha256
            || ready.source_sha256 != self.config.source_sha256
            || ready.profile != PROFILE
            || ready.projection != PROJECTION
            || ready.feature_format != contextdb_context::SEMANTIC_SCORING_FEATURE_SCHEMA
            || ready.quality != "development_only"
        {
            return Err(refused("worker READY binding differs"));
        }
        Ok(())
    }

    fn lock(&self, budget: &mut QueryBudget, deadline: Instant) -> Result<MutexGuard<'_, State>> {
        loop {
            budget
                .check()
                .map_err(|_| refused("worker allowance exhausted"))?;
            if Instant::now() >= deadline {
                return Err(refused("worker callback deadline exceeded"));
            }
            match self.state.try_lock() {
                Ok(state) => return Ok(state),
                Err(TryLockError::Poisoned(_)) => return Err(refused("worker state unavailable")),
                Err(TryLockError::WouldBlock) => {
                    budget
                        .charge(1, 0)
                        .map_err(|_| refused("worker queue allowance exhausted"))?;
                    thread::sleep(
                        Duration::from_millis(1)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
            }
        }
    }

    fn callback(
        &self,
        unit: &SemanticScoringUnit<'_>,
        budget: &mut QueryBudget,
        process: &mut Process,
        deadline: Instant,
        before_work: u64,
    ) -> Result<Option<u64>> {
        if unit.budget.remaining_scorer_work < self.config.limits.inference_work {
            return Err(refused("worker scorer work exhausted"));
        }
        budget
            .charge(self.config.limits.inference_work, 0)
            .map_err(|_| refused("worker inference reservation refused"))?;
        let input = unit.model_input_json(budget)?;
        // Account hash scan, transport copy and bounded reply/metadata before allocation.
        budget
            .charge(
                1,
                (input.len() as u64).saturating_mul(2) + (MAX_META * 3) as u64,
            )
            .map_err(|_| refused("worker transport allowance exhausted"))?;
        let input_digest = sha256(&input);
        let mut id = self
            .next_id
            .try_lock()
            .map_err(|_| refused("worker correlation unavailable"))?;
        let current = *id;
        *id = id
            .checked_add(1)
            .ok_or_else(|| refused("worker correlation exhausted"))?;
        drop(id);
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_micros();
        let timeout_micros = u64::try_from(remaining).unwrap_or(u64::MAX).min(
            budget
                .remaining_timeout_micros()
                .map_err(|_| refused("worker deadline exhausted"))?,
        );
        if timeout_micros == 0 {
            return Err(refused("worker deadline exhausted"));
        }
        let metadata = serde_json::to_vec(&ScoreRequest {
            format: FORMAT,
            operation: "score",
            id: current,
            config_sha256: &self.config_digest,
            input_bytes: input.len(),
            input_sha256: &input_digest,
            timeout_micros,
        })
        .map_err(|_| refused("worker metadata refused"))?;
        let frame = transport::frame(&metadata, input)?;
        budget
            .check()
            .map_err(|_| refused("worker allowance exhausted"))?;
        if before_work.saturating_sub(budget.remaining_work()) > unit.budget.remaining_scorer_work {
            return Err(refused("worker aggregate scorer work exhausted"));
        }
        if Instant::now() >= deadline {
            return Err(refused("worker callback deadline exceeded"));
        }
        let bytes = process.exchange(frame, deadline, budget)?;
        let reply: ScoreReply =
            serde_json::from_slice(&bytes).map_err(|_| refused("worker reply invalid"))?;
        validate_reply(reply, current, &self.config_digest, &input_digest)
    }
}

impl ContextScorer for KevScorer {
    fn failure_policy(&self) -> ScorerFailurePolicy {
        ScorerFailurePolicy::Refuse
    }
    fn id(&self) -> &str {
        SCORER
    }
    fn revision(&self) -> &str {
        &self.revision
    }
    fn latency_limit_micros(&self) -> u64 {
        self.config.limits.aggregate_timeout_micros
    }
    fn semantic_profile(&self) -> Option<SemanticScoringProfile> {
        Some(SemanticScoringProfile::RenderedClosureV1)
    }
    fn score(&self, _: &ScoringUnit, _: &mut QueryBudget) -> Result<Option<u64>> {
        Err(refused("development Kev requires actual semantic material"))
    }
    fn score_semantic(
        &self,
        unit: &SemanticScoringUnit<'_>,
        budget: &mut QueryBudget,
    ) -> Result<Option<u64>> {
        let before_work = budget.remaining_work();
        let timeout = budget
            .remaining_timeout_micros()
            .map_err(|_| refused("worker allowance exhausted"))?
            .min(unit.budget.remaining_timeout_micros)
            .min(unit.budget.remaining_scorer_micros)
            .min(self.config.limits.per_call_timeout_micros);
        if timeout == 0 {
            return Err(refused("worker callback has no time"));
        }
        let deadline = Instant::now() + Duration::from_micros(timeout);
        let mut state = self.lock(budget, deadline)?;
        let result = match &mut *state {
            State::Live(process) => self.callback(unit, budget, process, deadline, before_work),
            _ => Err(refused("worker is not admitted")),
        };
        if result.is_err() {
            *state = State::Closed;
        }
        result
    }
}

fn utility(logit: f64) -> Result<Option<u64>> {
    if !logit.is_finite() || logit.abs() > 1_000_000.0 {
        return Err(refused("worker score nonfinite or excessive"));
    }
    let probability = if logit >= 0.0 {
        1.0 / (1.0 + (-logit).exp())
    } else {
        let exp = logit.exp();
        exp / (1.0 + exp)
    };
    if probability <= 0.5 {
        return Ok(None);
    }
    let micros = contextdb_context::router::finite_micros(2.0 * probability - 1.0)?;
    Ok((micros > 0).then_some(micros))
}

fn validate_reply(
    reply: ScoreReply,
    expected_id: u64,
    expected_config: &str,
    expected_input: &str,
) -> Result<Option<u64>> {
    let (format, operation, id, config, input, value) = match reply {
        ScoreReply::Ok {
            format,
            operation,
            id,
            config_sha256,
            input_sha256,
            yes_minus_no,
        } => (
            format,
            operation,
            id,
            config_sha256,
            input_sha256,
            Ok(yes_minus_no),
        ),
        ScoreReply::Error {
            format,
            operation,
            id,
            config_sha256,
            input_sha256,
            code,
        } => {
            let error = match code {
                ReplyCode::ProjectionRefused => {
                    ContextError::InvalidRequest("worker semantic projection unsupported".into())
                }
                ReplyCode::TokenRefused => {
                    ContextError::Tokenizer("worker token admission refused".into())
                }
                ReplyCode::DeadlineRefused => {
                    ContextError::BudgetExceeded("worker inference deadline refused".into())
                }
                ReplyCode::ResourceRefused => {
                    ContextError::BudgetExceeded("worker inference resource refused".into())
                }
                ReplyCode::InferenceRefused => refused("worker inference refused"),
                ReplyCode::NonfiniteScore => refused("worker score nonfinite"),
            };
            (
                format,
                operation,
                id,
                config_sha256,
                input_sha256,
                Err(error),
            )
        }
    };
    if format != FORMAT
        || operation != "score"
        || id != expected_id
        || config != expected_config
        || input != expected_input
    {
        return Err(refused("worker reply association differs"));
    }
    value.and_then(utility)
}

fn refused(message: &'static str) -> ContextError {
    ContextError::RouterScore(message.into())
}
fn error(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::ProviderUnavailable, message, false)
}
fn context_error(_: ContextError) -> ServiceError {
    error("development Kev worker refused")
}

#[cfg(test)]
pub(in crate::owned_conversation) mod tests;
