//! Trusted owner installation and current admission before each learned callback.

use super::*;
use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard, TryLockError},
    time::{Duration, Instant},
};

pub(crate) struct InstalledScorer {
    backend: Arc<dyn ContextScorer>,
    id: String,
    revision: String,
    latency: u64,
    gate: Mutex<()>,
}

impl NativeService {
    /// Installs one immutable trusted local preparation scorer before sharing this
    /// owner. Its executable/bundle configuration belongs to the host, never to
    /// conversation input. Protected tracing and ModelProcessing are required on
    /// each use; installation grants no source access or training permission.
    /// Without installation, all existing profiles retain their R0 path and costs.
    pub fn with_preparation_scorer(
        mut self,
        scorer: Arc<dyn ContextScorer>,
    ) -> ServiceResult<Self> {
        if self.preparation_scorer.is_some() {
            return Err(invalid("preparation scorer is already installed"));
        }
        let id = scorer.id();
        let revision = scorer.revision();
        if scorer.semantic_profile() != Some(SemanticScoringProfile::RenderedClosureV1)
            || id.trim().is_empty()
            || id.len() > 256
            || id.contains('\0')
            || revision.trim().is_empty()
            || revision.len() > 1024
            || revision.contains('\0')
            || !(1..=10_000_000).contains(&scorer.latency_limit_micros())
        {
            return Err(invalid(
                "preparation scorer requires a bounded immutable semantic profile",
            ));
        }
        let installed = InstalledScorer {
            id: id.into(),
            revision: revision.into(),
            latency: scorer.latency_limit_micros(),
            backend: scorer,
            gate: Mutex::new(()),
        };
        installed.check_stable()?;
        self.preparation_scorer = Some(installed);
        Ok(self)
    }
}

impl InstalledScorer {
    pub(super) fn check_stable(&self) -> ServiceResult<()> {
        if self.backend.id() != self.id
            || self.backend.revision() != self.revision
            || self.backend.latency_limit_micros() != self.latency
            || self.backend.semantic_profile() != Some(SemanticScoringProfile::RenderedClosureV1)
        {
            return Err(invalid("installed preparation scorer binding changed"));
        }
        Ok(())
    }

    fn enter(
        &self,
        unit: &SemanticScoringUnit<'_>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<MutexGuard<'_, ()>> {
        let remaining = budget
            .remaining_timeout_micros()
            .map_err(budget_error)?
            .min(unit.budget.remaining_scorer_micros)
            .min(self.latency);
        if remaining == 0 {
            return Err(super::super::exhausted("learned scorer deadline exhausted"));
        }
        let deadline = Instant::now() + Duration::from_micros(remaining);
        loop {
            budget.check().map_err(budget_error)?;
            if Instant::now() >= deadline {
                return Err(super::super::exhausted(
                    "learned scorer queue deadline exhausted",
                ));
            }
            match self.gate.try_lock() {
                Ok(guard) => return Ok(guard),
                Err(TryLockError::Poisoned(_)) => {
                    return Err(super::super::integrity("learned scorer gate poisoned"));
                }
                Err(TryLockError::WouldBlock) => {
                    budget.charge(1, 0).map_err(budget_error)?;
                    std::thread::sleep(
                        Duration::from_millis(1)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
            }
        }
    }
}

pub(super) struct CurrentScorer<'a> {
    service: &'a NativeService,
    context: &'a AuthenticatedRequestContext,
    fence: &'a PrepareFence,
    controls: &'a RouterTraceControls,
    installed: &'a InstalledScorer,
    failure: Mutex<Option<ServiceError>>,
}

impl<'a> CurrentScorer<'a> {
    pub(super) fn new(
        service: &'a NativeService,
        context: &'a AuthenticatedRequestContext,
        fence: &'a PrepareFence,
        controls: &'a RouterTraceControls,
        installed: &'a InstalledScorer,
    ) -> Self {
        Self {
            service,
            context,
            fence,
            controls,
            installed,
            failure: Mutex::new(None),
        }
    }

    pub(super) fn take_failure(&self) -> Option<ServiceError> {
        self.failure
            .lock()
            .ok()
            .and_then(|mut failure| failure.take())
    }

    fn refuse(&self, error: ServiceError) -> ContextError {
        if let Ok(mut failure) = self.failure.lock() {
            *failure = Some(error);
        }
        ContextError::Authorization("current learned processing admission refused".into())
    }
}

impl fmt::Debug for CurrentScorer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CurrentPreparationScorer")
            .finish_non_exhaustive()
    }
}

impl ContextScorer for CurrentScorer<'_> {
    fn id(&self) -> &str {
        &self.installed.id
    }
    fn revision(&self) -> &str {
        &self.installed.revision
    }
    fn latency_limit_micros(&self) -> u64 {
        self.installed.latency
    }
    fn semantic_profile(&self) -> Option<SemanticScoringProfile> {
        Some(SemanticScoringProfile::RenderedClosureV1)
    }
    fn failure_policy(&self) -> ScorerFailurePolicy {
        ScorerFailurePolicy::Refuse
    }
    fn score(&self, _: &ScoringUnit, _: &mut QueryBudget) -> Result<Option<u64>> {
        Err(ContextError::RouterScore(
            "installed semantic scorer has no scalar route".into(),
        ))
    }
    fn score_semantic(
        &self,
        unit: &SemanticScoringUnit<'_>,
        budget: &mut QueryBudget,
    ) -> Result<Option<u64>> {
        let started = Instant::now();
        let before_work = budget.remaining_work();
        // This scorer gate serializes this owner's callbacks before admission.
        // It is not a native publication writer and grants no authority.
        let _slot = self
            .installed
            .enter(unit, budget)
            .map_err(|error| self.refuse(error))?;
        let admission = (|| {
            require_capability(self.context, Capability::ModelProcessing)?;
            self.installed.check_stable()?;
            budget.charge(1, 0).map_err(budget_error)?;
            let snapshot = self
                .service
                .engine
                .begin_read(SnapshotSelector::Latest)
                .map_err(storage_error)?;
            self.service
                .check_prepare_fence_in(&snapshot, self.context, self.fence, budget)?;
            self.service.authorize_router_trace_controls(
                &snapshot,
                self.context,
                self.controls,
                budget,
            )?;
            natural::validate_unit(unit, budget)
        })();
        admission.map_err(|error| self.refuse(error))?;
        let elapsed = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let mut allowance = unit.budget;
        allowance.remaining_work = budget.remaining_work();
        allowance.remaining_bytes = budget.remaining_bytes();
        allowance.remaining_timeout_micros = unit
            .budget
            .remaining_timeout_micros
            .saturating_sub(elapsed)
            .min(
                budget
                    .remaining_timeout_micros()
                    .map_err(|error| self.refuse(budget_error(error)))?,
            );
        allowance.remaining_scorer_work = unit
            .budget
            .remaining_scorer_work
            .saturating_sub(before_work.saturating_sub(budget.remaining_work()));
        allowance.remaining_scorer_micros =
            unit.budget.remaining_scorer_micros.saturating_sub(elapsed);
        if allowance.remaining_timeout_micros == 0
            || allowance.remaining_scorer_micros == 0
            || allowance.remaining_scorer_work == 0
        {
            return Err(self.refuse(super::super::exhausted(
                "learned scorer admission allowance exhausted",
            )));
        }
        let admitted_unit = unit.with_reduced_allowance(allowance);
        // Current admission follows the established dispatch contract. No native
        // writer is held over model I/O; this is not atomic revocation/pipe handoff.
        // The trusted backend must be exclusive to this owner and honor the same
        // remaining allowance before serialization, I/O and accepting a result.
        let value = self
            .installed
            .backend
            .score_semantic(&admitted_unit, budget)
            .map_err(|error| {
                let error = match error {
                    ContextError::RouterScore(_) => ServiceError::new(
                        contextdb_service::ErrorCode::ProviderUnavailable,
                        "installed preparation scorer unavailable",
                        false,
                    ),
                    other => service_error(other),
                };
                self.refuse(error)
            })?;
        self.installed
            .check_stable()
            .map_err(|error| self.refuse(error))?;
        budget
            .check()
            .map_err(|error| self.refuse(budget_error(error)))?;
        Ok(value)
    }
}
