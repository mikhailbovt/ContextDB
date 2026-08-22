use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, RwLock};

use contextdb_core::{ContentDigest, ModelCallId};

use crate::provider::ProviderRequestParts;
use crate::types::{canonical_digest, digest_parts};
use crate::{
    AttemptKind, AvailabilityRegistry, CapabilityRegistry, CircuitBreaker, CircuitBreakerConfig,
    CircuitKey, DeterministicFallbackRequest, EvaluatedRoute, FallbackRegistry, ModelAuditEvent,
    ModelAuditSink, ModelCallFinished, ModelCallStarted, ModelCallStatus, ModelCapability,
    ModelExecutionPath, ModelInput, ModelProvider, ModelRuntimeError, ModelUsage, PromptAssetRef,
    PromptRegistry, ProviderAttemptContext, ProviderError, ProviderErrorKind, ProviderId,
    ProviderRequest, RepairContext, RepairViolation, Result, RetryPolicy, RouteSummary,
    RoutingPolicy, RuntimeTimer, SchemaRef, SchemaRegistry, StructuredFormat, SystemTimer,
    ValidatedModelProposal, evaluate_routes,
};

/// Complete provider-neutral request to the model gateway.
#[derive(Clone, Debug)]
pub struct ModelCallRequest {
    /// Specialized operation.
    pub capability: ModelCapability,
    /// Exact prompt asset.
    pub prompt: PromptAssetRef,
    /// Exact structured output schema.
    pub output_schema: SchemaRef,
    /// Protected input envelope.
    pub input: ModelInput,
    /// Effective privacy/cost/latency/quality policy.
    pub routing_policy: RoutingPolicy,
    /// Maximum provider output tokens.
    pub max_output_tokens: u32,
    /// Whether a registered deterministic no-model path may run after provider
    /// routes are absent or fail.
    pub allow_deterministic_fallback: bool,
}

/// Gateway reliability and caching configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelGatewayConfig {
    /// Bounded retry/deadline policy.
    pub retry: RetryPolicy,
    /// Circuit-breaker policy.
    pub circuit_breaker: CircuitBreakerConfig,
    /// Cache only schema-validated production proposals.
    pub enable_validated_cache: bool,
}

impl Default for ModelGatewayConfig {
    fn default() -> Self {
        Self {
            retry: RetryPolicy::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            enable_validated_cache: true,
        }
    }
}

impl ModelGatewayConfig {
    fn validate(self) -> Result<()> {
        self.retry.validate()?;
        self.circuit_breaker.validate()
    }
}

/// Why a model-assisted operation returned safely without a proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegradedReason {
    /// Registry/policy had no compatible provider route.
    NoCompatibleRoute,
    /// Every provider route failed, timed out, refused, or had an open circuit.
    ProviderUnavailable,
    /// No deterministic rule applied after provider failure.
    DeterministicUnavailable,
    /// Total call deadline elapsed.
    DeadlineExceeded,
}

/// Explicit degraded-mode result. Durable capture and deterministic database
/// operations remain usable; semantic freshness may lag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DegradedModelOutcome {
    /// Requested capability.
    pub capability: ModelCapability,
    /// Safe reason.
    pub reason: DegradedReason,
    /// Provider failure never invalidates already durable raw input.
    pub durable_capture_affected: bool,
    /// Model-assisted projections may lag.
    pub semantic_freshness_degraded: bool,
}

/// Execution metadata returned with a validated proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelExecution {
    /// Audit call identity.
    pub call_id: ModelCallId,
    /// Provider, cache, or no-model fallback.
    pub path: ModelExecutionPath,
    /// Provider route when applicable.
    pub route: Option<RouteSummary>,
    /// Provider-safe usage metadata.
    pub usage: ModelUsage,
    /// True for deterministic degraded mode.
    pub degraded: bool,
}

/// Validated gateway result. It is still a proposal, never a semantic mutation.
#[derive(Clone, Debug)]
pub struct ValidatedModelResult {
    /// Opaque schema-validated proposal.
    pub proposal: ValidatedModelProposal,
    /// Payload-free execution metadata.
    pub execution: ModelExecution,
}

/// Model gateway outcome.
#[derive(Clone, Debug)]
pub enum ModelGatewayOutcome {
    /// Provider/cache/fallback output passed every schema validator.
    Validated(Box<ValidatedModelResult>),
    /// Safe no-model degraded operation with no proposal.
    Degraded(DegradedModelOutcome),
}

/// Isolated shadow result. No validated proposal or raw output is exposed, and
/// shadow calls never populate production cache or circuit state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowEvaluation {
    /// Audit call identity.
    pub call_id: ModelCallId,
    /// Evaluated route.
    pub route: RouteSummary,
    /// Terminal status.
    pub status: ModelCallStatus,
    /// Output digest, if bytes were returned.
    pub output_digest: Option<ContentDigest>,
    /// True only when strict structural and semantic validation passed.
    pub schema_valid: bool,
    /// Provider-safe usage metadata.
    pub usage: ModelUsage,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CacheKey {
    capability: ModelCapability,
    provider: ProviderId,
    model_revision: crate::ModelRevision,
    prompt_digest: ContentDigest,
    schema_digest: ContentDigest,
    input_digest: ContentDigest,
    policy_digest: ContentDigest,
}

#[derive(Clone, Debug)]
struct CachedProposal {
    proposal: ValidatedModelProposal,
    route: RouteSummary,
    usage: ModelUsage,
}

/// Unified provider-neutral gateway.
pub struct ModelGateway {
    registry: Arc<CapabilityRegistry>,
    schemas: Arc<SchemaRegistry>,
    prompts: Arc<PromptRegistry>,
    fallbacks: Arc<FallbackRegistry>,
    audit: Arc<dyn ModelAuditSink>,
    timer: Arc<dyn RuntimeTimer>,
    config: ModelGatewayConfig,
    providers: RwLock<BTreeMap<ProviderId, Arc<dyn ModelProvider>>>,
    cache: RwLock<BTreeMap<CacheKey, CachedProposal>>,
    circuits: CircuitBreaker,
    availability: AvailabilityRegistry,
}

impl fmt::Debug for ModelGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelGateway")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl ModelGateway {
    /// Creates a gateway using the production monotonic timer.
    pub fn new(
        registry: Arc<CapabilityRegistry>,
        schemas: Arc<SchemaRegistry>,
        prompts: Arc<PromptRegistry>,
        fallbacks: Arc<FallbackRegistry>,
        audit: Arc<dyn ModelAuditSink>,
        config: ModelGatewayConfig,
    ) -> Result<Self> {
        Self::with_timer(
            registry,
            schemas,
            prompts,
            fallbacks,
            audit,
            Arc::new(SystemTimer::new()),
            config,
        )
    }

    /// Creates a gateway with an injected timer for deterministic tests and
    /// host schedulers.
    pub fn with_timer(
        registry: Arc<CapabilityRegistry>,
        schemas: Arc<SchemaRegistry>,
        prompts: Arc<PromptRegistry>,
        fallbacks: Arc<FallbackRegistry>,
        audit: Arc<dyn ModelAuditSink>,
        timer: Arc<dyn RuntimeTimer>,
        config: ModelGatewayConfig,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            registry,
            schemas,
            prompts,
            fallbacks,
            audit,
            timer,
            config,
            providers: RwLock::new(BTreeMap::new()),
            cache: RwLock::new(BTreeMap::new()),
            circuits: CircuitBreaker::new(config.circuit_breaker)?,
            availability: AvailabilityRegistry::default(),
        })
    }

    /// Registers an isolated adapter implementation. The adapter identity must
    /// match capability routes, and duplicate registrations fail closed.
    pub fn register_provider(&self, provider: Arc<dyn ModelProvider>) -> Result<()> {
        let id = provider.id().clone();
        let mut providers = self
            .providers
            .write()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        if providers.contains_key(&id) {
            return Err(ModelRuntimeError::RegistryConflict(format!(
                "provider adapter {id}"
            )));
        }
        providers.insert(id, provider);
        Ok(())
    }

    /// Executes a production request. Every returned proposal has passed the
    /// exact registered schema and semantic validator.
    pub fn execute(&self, request: &ModelCallRequest) -> Result<ModelGatewayOutcome> {
        let (prompt, routes) = self.prepare_request(request)?;
        let started_at = self.timer.now_ms();
        let total_deadline = started_at
            .checked_add(self.config.retry.total_timeout_ms)
            .ok_or(ModelRuntimeError::ArithmeticOverflow)?;
        let mut provider_failed = false;
        for route in routes {
            if self.timer.now_ms() >= total_deadline {
                return self.degraded_or_fallback(
                    request,
                    DegradedReason::DeadlineExceeded,
                    &prompt.reference,
                );
            }
            match self.execute_route(request, &prompt.system_text, &route, total_deadline)? {
                Some(result) => return Ok(ModelGatewayOutcome::Validated(Box::new(result))),
                None => provider_failed = true,
            }
        }
        let reason = if provider_failed {
            DegradedReason::ProviderUnavailable
        } else {
            DegradedReason::NoCompatibleRoute
        };
        self.degraded_or_fallback(request, reason, &prompt.reference)
    }

    /// Runs selected routes in isolated shadow mode. Shadow output is reduced to
    /// digest/status/usage and cannot enter the production cache.
    pub fn evaluate_shadow(
        &self,
        request: &ModelCallRequest,
        providers: &BTreeSet<ProviderId>,
    ) -> Result<Vec<ShadowEvaluation>> {
        let (prompt, routes) = self.prepare_request(request)?;
        let mut evaluations = Vec::new();
        for route in routes
            .into_iter()
            .filter(|route| providers.is_empty() || providers.contains(&route.route.provider))
        {
            let Some(provider) = self.provider(&route.route.provider)? else {
                continue;
            };
            let started_at = self.timer.now_ms();
            let deadline = started_at
                .checked_add(self.config.retry.per_attempt_timeout_ms)
                .ok_or(ModelRuntimeError::ArithmeticOverflow)?;
            let call_id = ModelCallId::new();
            let provider_request = ProviderRequest::from_parts(ProviderRequestParts {
                capability: request.capability.clone(),
                model_profile: route.route.descriptor.model_profile,
                model_revision: route.route.model_revision.clone(),
                prompt: prompt.reference.clone(),
                output_schema: request.output_schema.clone(),
                max_output_tokens: request.max_output_tokens,
                system_prompt: Arc::from(prompt.system_text.clone()),
                input: route.input.clone(),
            });
            self.audit_start(ModelCallStarted {
                id: call_id,
                capability: request.capability.clone(),
                path: ModelExecutionPath::Provider,
                provider: Some(route.route.provider.clone()),
                model_profile: Some(route.route.descriptor.model_profile),
                model_revision: Some(route.route.model_revision.clone()),
                prompt: prompt.reference.clone(),
                schema: request.output_schema.clone(),
                input_digest: route.input.digest,
                source_refs: route.input.source_refs.clone(),
                started_at_ms: started_at,
                attempt: 1,
                retry_of: None,
                shadow: true,
                policy_decision: Some(route.decision.clone()),
            })?;
            let response = provider.invoke(
                &provider_request,
                &ProviderAttemptContext {
                    call_id,
                    attempt: 1,
                    idempotency_key: provider_idempotency_key(request, &route, None, true)?,
                    deadline_ms: deadline,
                    kind: AttemptKind::Shadow,
                },
            );
            let finished_at = self.timer.now_ms();
            let (status, output_digest, schema_valid, usage) = self.classify_shadow_response(
                &request.output_schema,
                response,
                deadline,
                finished_at,
            );
            self.audit_finish(ModelCallFinished {
                id: call_id,
                status,
                output_digest,
                latency_ms: finished_at.saturating_sub(started_at),
                usage,
            })?;
            evaluations.push(ShadowEvaluation {
                call_id,
                route: route_summary(&route),
                status,
                output_digest,
                schema_valid,
                usage,
            });
        }
        Ok(evaluations)
    }

    fn prepare_request(
        &self,
        request: &ModelCallRequest,
    ) -> Result<(Arc<crate::PromptAsset>, Vec<EvaluatedRoute>)> {
        request.capability.validate()?;
        if request.max_output_tokens == 0 {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "model_call.max_output_tokens",
                reason: "must be positive",
            });
        }
        if !self.schemas.contains(&request.output_schema) {
            return Err(ModelRuntimeError::SchemaUnavailable(
                request.output_schema.clone(),
            ));
        }
        let prompt = self.prompts.get(&request.prompt)?;
        let allocated_tokens = request
            .input
            .input_tokens
            .checked_add(request.max_output_tokens)
            .ok_or(ModelRuntimeError::ArithmeticOverflow)?;
        if prompt.capability != request.capability
            || prompt.output_schema != request.output_schema
            || allocated_tokens > prompt.token_budget
            || request
                .input
                .language
                .as_ref()
                .is_some_and(|language| !prompt.evaluated_languages.contains(language))
        {
            return Err(ModelRuntimeError::PromptMismatch);
        }
        let complexity = self.schemas.complexity(&request.output_schema)?;
        let routes = evaluate_routes(
            self.registry
                .routes_for(&request.capability, &request.output_schema)?,
            &request.input,
            &request.capability,
            request.max_output_tokens,
            &request.routing_policy,
        )?
        .into_iter()
        .filter(|route| {
            let Ok(profile) = self.registry.profile(route.route.descriptor.model_profile) else {
                return false;
            };
            let total_tokens = request
                .input
                .input_tokens
                .saturating_add(request.max_output_tokens);
            profile.preferred_structured_format == StructuredFormat::JsonSchema
                && complexity <= profile.max_schema_complexity
                && total_tokens <= profile.max_context_tokens
                && request.max_output_tokens <= profile.reserved_output_tokens
                && route.route.descriptor.benchmark_score >= prompt.minimum_golden_score
                && route.route.descriptor.benchmark_score >= prompt.minimum_adversarial_score
                && route.input.sensitivity <= prompt.privacy_classification
        })
        .collect();
        Ok((prompt, routes))
    }

    fn execute_route(
        &self,
        request: &ModelCallRequest,
        system_prompt: &str,
        route: &EvaluatedRoute,
        total_deadline: u64,
    ) -> Result<Option<ValidatedModelResult>> {
        let Some(provider) = self.provider(&route.route.provider)? else {
            return Ok(None);
        };
        let cache_key = cache_key(request, route);
        if self.config.enable_validated_cache
            && let Some(cached) = self
                .cache
                .read()
                .map_err(|_| ModelRuntimeError::LockPoisoned)?
                .get(&cache_key)
                .cloned()
        {
            return self.audit_cache_hit(request, route, cached).map(Some);
        }
        let circuit_key = CircuitKey {
            provider: route.route.provider.clone(),
            model_revision: route.route.model_revision.clone(),
            capability: request.capability.clone(),
        };
        let provider_request = ProviderRequest::from_parts(ProviderRequestParts {
            capability: request.capability.clone(),
            model_profile: route.route.descriptor.model_profile,
            model_revision: route.route.model_revision.clone(),
            prompt: request.prompt.clone(),
            output_schema: request.output_schema.clone(),
            max_output_tokens: request.max_output_tokens,
            system_prompt: Arc::from(system_prompt.to_owned()),
            input: route.input.clone(),
        });
        let mut previous_call = None;
        let mut repair = None;
        let mut repairs = 0_u8;
        for attempt in 1..=self.config.retry.max_attempts {
            let now = self.timer.now_ms();
            if now >= total_deadline
                || !self.availability.available(&route.route.provider, now)?
                || !self.circuits.allow(&circuit_key, now)?
            {
                return Ok(None);
            }
            let deadline = now
                .checked_add(self.config.retry.per_attempt_timeout_ms)
                .ok_or(ModelRuntimeError::ArithmeticOverflow)?
                .min(total_deadline);
            let call_id = ModelCallId::new();
            self.audit_start(ModelCallStarted {
                id: call_id,
                capability: request.capability.clone(),
                path: ModelExecutionPath::Provider,
                provider: Some(route.route.provider.clone()),
                model_profile: Some(route.route.descriptor.model_profile),
                model_revision: Some(route.route.model_revision.clone()),
                prompt: request.prompt.clone(),
                schema: request.output_schema.clone(),
                input_digest: route.input.digest,
                source_refs: route.input.source_refs.clone(),
                started_at_ms: now,
                attempt,
                retry_of: previous_call,
                shadow: false,
                policy_decision: Some(route.decision.clone()),
            })?;
            let context = ProviderAttemptContext {
                call_id,
                attempt,
                idempotency_key: provider_idempotency_key(request, route, repair.as_ref(), false)?,
                deadline_ms: deadline,
                kind: repair
                    .clone()
                    .map_or(AttemptKind::Production, AttemptKind::SchemaRepair),
            };
            let response = provider.invoke(&provider_request, &context);
            let finished_at = self.timer.now_ms();
            if finished_at >= deadline {
                self.circuits.record_failure(
                    &circuit_key,
                    ProviderErrorKind::Timeout,
                    finished_at,
                )?;
                self.audit_finish(ModelCallFinished {
                    id: call_id,
                    status: ModelCallStatus::Timeout,
                    output_digest: response.as_ref().ok().map(|response| {
                        rejected_output_digest(&request.output_schema, &response.output)
                    }),
                    latency_ms: finished_at.saturating_sub(now),
                    usage: response
                        .as_ref()
                        .map_or(ModelUsage::default(), |response| response.usage),
                })?;
                previous_call = Some(call_id);
                if !self.delay_before_retry(attempt, None, total_deadline) {
                    return Ok(None);
                }
                continue;
            }
            match response {
                Ok(response) => {
                    self.circuits.record_success(&circuit_key)?;
                    match self
                        .schemas
                        .validate_raw(&request.output_schema, &response.output)
                    {
                        Ok(proposal) => {
                            self.audit_finish(ModelCallFinished {
                                id: call_id,
                                status: ModelCallStatus::Succeeded,
                                output_digest: Some(proposal.output_digest()),
                                latency_ms: finished_at.saturating_sub(now),
                                usage: response.usage,
                            })?;
                            let summary = route_summary(route);
                            if self.config.enable_validated_cache {
                                self.cache
                                    .write()
                                    .map_err(|_| ModelRuntimeError::LockPoisoned)?
                                    .insert(
                                        cache_key,
                                        CachedProposal {
                                            proposal: proposal.clone(),
                                            route: summary.clone(),
                                            usage: response.usage,
                                        },
                                    );
                            }
                            return Ok(Some(ValidatedModelResult {
                                proposal,
                                execution: ModelExecution {
                                    call_id,
                                    path: ModelExecutionPath::Provider,
                                    route: Some(summary),
                                    usage: response.usage,
                                    degraded: false,
                                },
                            }));
                        }
                        Err(error) => {
                            let rejected =
                                rejected_output_digest(&request.output_schema, &response.output);
                            self.audit_finish(ModelCallFinished {
                                id: call_id,
                                status: ModelCallStatus::SchemaRejected,
                                output_digest: Some(rejected),
                                latency_ms: finished_at.saturating_sub(now),
                                usage: response.usage,
                            })?;
                            previous_call = Some(call_id);
                            if repairs >= self.config.retry.max_schema_repairs
                                || attempt == self.config.retry.max_attempts
                            {
                                return Ok(None);
                            }
                            repairs = repairs.saturating_add(1);
                            repair = Some(RepairContext {
                                rejected_output_digest: rejected,
                                violation: repair_violation(&error),
                            });
                            if !self.delay_before_retry(attempt, None, total_deadline) {
                                return Ok(None);
                            }
                        }
                    }
                }
                Err(error) => {
                    self.circuits
                        .record_failure(&circuit_key, error.kind, finished_at)?;
                    if error.kind == ProviderErrorKind::RateLimited
                        && let Some(delay) = error.retry_after_ms
                    {
                        let unavailable_until = finished_at.saturating_add(delay);
                        self.availability
                            .mark_unavailable(route.route.provider.clone(), unavailable_until)?;
                    }
                    self.audit_finish(ModelCallFinished {
                        id: call_id,
                        status: provider_status(error.kind),
                        output_digest: None,
                        latency_ms: finished_at.saturating_sub(now),
                        usage: ModelUsage::default(),
                    })?;
                    previous_call = Some(call_id);
                    if !error.kind.retryable()
                        || !self.delay_before_retry(attempt, error.retry_after_ms, total_deadline)
                    {
                        return Ok(None);
                    }
                }
            }
        }
        Ok(None)
    }

    fn audit_cache_hit(
        &self,
        request: &ModelCallRequest,
        route: &EvaluatedRoute,
        cached: CachedProposal,
    ) -> Result<ValidatedModelResult> {
        let call_id = ModelCallId::new();
        let now = self.timer.now_ms();
        self.audit_start(ModelCallStarted {
            id: call_id,
            capability: request.capability.clone(),
            path: ModelExecutionPath::ValidatedCache,
            provider: Some(route.route.provider.clone()),
            model_profile: Some(route.route.descriptor.model_profile),
            model_revision: Some(route.route.model_revision.clone()),
            prompt: request.prompt.clone(),
            schema: request.output_schema.clone(),
            input_digest: route.input.digest,
            source_refs: route.input.source_refs.clone(),
            started_at_ms: now,
            attempt: 1,
            retry_of: None,
            shadow: false,
            policy_decision: Some(route.decision.clone()),
        })?;
        self.audit_finish(ModelCallFinished {
            id: call_id,
            status: ModelCallStatus::CacheHit,
            output_digest: Some(cached.proposal.output_digest()),
            latency_ms: 0,
            usage: cached.usage,
        })?;
        Ok(ValidatedModelResult {
            proposal: cached.proposal,
            execution: ModelExecution {
                call_id,
                path: ModelExecutionPath::ValidatedCache,
                route: Some(cached.route),
                usage: cached.usage,
                degraded: false,
            },
        })
    }

    fn degraded_or_fallback(
        &self,
        request: &ModelCallRequest,
        reason: DegradedReason,
        prompt: &PromptAssetRef,
    ) -> Result<ModelGatewayOutcome> {
        if request.allow_deterministic_fallback
            && request.input.sensitivity != crate::Sensitivity::Secret
            && let Some(fallback) = self
                .fallbacks
                .get(&request.capability, &request.output_schema)?
        {
            let input = request.input.protected_for_fallback();
            let call_id = ModelCallId::new();
            let now = self.timer.now_ms();
            self.audit_start(ModelCallStarted {
                id: call_id,
                capability: request.capability.clone(),
                path: ModelExecutionPath::DeterministicFallback,
                provider: None,
                model_profile: None,
                model_revision: None,
                prompt: prompt.clone(),
                schema: request.output_schema.clone(),
                input_digest: input.digest,
                source_refs: input.source_refs.clone(),
                started_at_ms: now,
                attempt: 1,
                retry_of: None,
                shadow: false,
                policy_decision: None,
            })?;
            let output = match fallback.evaluate(&DeterministicFallbackRequest {
                capability: request.capability.clone(),
                output_schema: request.output_schema.clone(),
                prompt: prompt.clone(),
                input,
                max_output_tokens: request.max_output_tokens,
            }) {
                Ok(output) => output,
                Err(_) => {
                    self.audit_finish(ModelCallFinished {
                        id: call_id,
                        status: ModelCallStatus::Failed,
                        output_digest: None,
                        latency_ms: self.timer.now_ms().saturating_sub(now),
                        usage: ModelUsage::default(),
                    })?;
                    return Ok(ModelGatewayOutcome::Degraded(DegradedModelOutcome {
                        capability: request.capability.clone(),
                        reason: DegradedReason::DeterministicUnavailable,
                        durable_capture_affected: false,
                        semantic_freshness_degraded: true,
                    }));
                }
            };
            if let Some(output) = output {
                let proposal = match self.schemas.validate_raw(&request.output_schema, &output) {
                    Ok(proposal) => proposal,
                    Err(error) => {
                        self.audit_finish(ModelCallFinished {
                            id: call_id,
                            status: ModelCallStatus::SchemaRejected,
                            output_digest: Some(rejected_output_digest(
                                &request.output_schema,
                                &output,
                            )),
                            latency_ms: self.timer.now_ms().saturating_sub(now),
                            usage: ModelUsage::default(),
                        })?;
                        return Err(error);
                    }
                };
                self.audit_finish(ModelCallFinished {
                    id: call_id,
                    status: ModelCallStatus::DeterministicFallback,
                    output_digest: Some(proposal.output_digest()),
                    latency_ms: self.timer.now_ms().saturating_sub(now),
                    usage: ModelUsage::default(),
                })?;
                return Ok(ModelGatewayOutcome::Validated(Box::new(
                    ValidatedModelResult {
                        proposal,
                        execution: ModelExecution {
                            call_id,
                            path: ModelExecutionPath::DeterministicFallback,
                            route: None,
                            usage: ModelUsage::default(),
                            degraded: true,
                        },
                    },
                )));
            }
            self.audit_finish(ModelCallFinished {
                id: call_id,
                status: ModelCallStatus::ProviderUnavailable,
                output_digest: None,
                latency_ms: self.timer.now_ms().saturating_sub(now),
                usage: ModelUsage::default(),
            })?;
            return Ok(ModelGatewayOutcome::Degraded(DegradedModelOutcome {
                capability: request.capability.clone(),
                reason: DegradedReason::DeterministicUnavailable,
                durable_capture_affected: false,
                semantic_freshness_degraded: true,
            }));
        }
        Ok(ModelGatewayOutcome::Degraded(DegradedModelOutcome {
            capability: request.capability.clone(),
            reason,
            durable_capture_affected: false,
            semantic_freshness_degraded: true,
        }))
    }

    fn classify_shadow_response(
        &self,
        schema: &SchemaRef,
        response: std::result::Result<crate::ProviderResponse, ProviderError>,
        deadline: u64,
        finished_at: u64,
    ) -> (ModelCallStatus, Option<ContentDigest>, bool, ModelUsage) {
        if finished_at >= deadline {
            let digest = response
                .as_ref()
                .ok()
                .map(|response| rejected_output_digest(schema, &response.output));
            let usage = response
                .as_ref()
                .map_or(ModelUsage::default(), |response| response.usage);
            return (ModelCallStatus::Timeout, digest, false, usage);
        }
        match response {
            Ok(response) => match self.schemas.validate_raw(schema, &response.output) {
                Ok(proposal) => (
                    ModelCallStatus::Succeeded,
                    Some(proposal.output_digest()),
                    true,
                    response.usage,
                ),
                Err(_) => (
                    ModelCallStatus::SchemaRejected,
                    Some(rejected_output_digest(schema, &response.output)),
                    false,
                    response.usage,
                ),
            },
            Err(error) => (
                provider_status(error.kind),
                None,
                false,
                ModelUsage::default(),
            ),
        }
    }

    fn provider(&self, id: &ProviderId) -> Result<Option<Arc<dyn ModelProvider>>> {
        Ok(self
            .providers
            .read()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?
            .get(id)
            .cloned())
    }

    fn delay_before_retry(
        &self,
        attempt: u8,
        retry_after_ms: Option<u64>,
        total_deadline: u64,
    ) -> bool {
        if attempt >= self.config.retry.max_attempts {
            return false;
        }
        let delay = self.config.retry.delay_for(attempt, retry_after_ms);
        if self.timer.now_ms().saturating_add(delay) >= total_deadline {
            return false;
        }
        self.timer.delay_ms(delay);
        true
    }

    fn audit_start(&self, started: ModelCallStarted) -> Result<()> {
        self.audit
            .record(ModelAuditEvent::Started(Box::new(started)))
            .map_err(ModelRuntimeError::Audit)
    }

    fn audit_finish(&self, finished: ModelCallFinished) -> Result<()> {
        self.audit
            .record(ModelAuditEvent::Finished(finished))
            .map_err(ModelRuntimeError::Audit)
    }
}

fn cache_key(request: &ModelCallRequest, route: &EvaluatedRoute) -> CacheKey {
    CacheKey {
        capability: request.capability.clone(),
        provider: route.route.provider.clone(),
        model_revision: route.route.model_revision.clone(),
        prompt_digest: request.prompt.digest,
        schema_digest: request.output_schema.digest,
        input_digest: route.input.digest,
        policy_digest: route.decision.digest,
    }
}

fn route_summary(route: &EvaluatedRoute) -> RouteSummary {
    RouteSummary {
        capability: route.route.descriptor.capability.clone(),
        provider: route.route.provider.clone(),
        locality: route.route.descriptor.data_policy.locality,
        estimated_cost_micros: route.decision.estimated_cost_micros,
        estimated_cost_currency: route.decision.estimated_cost_currency.clone(),
        expected_p95_ms: route.route.descriptor.latency_profile.p95_ms,
    }
}

fn rejected_output_digest(schema: &SchemaRef, output: &[u8]) -> ContentDigest {
    digest_parts(
        b"contextdb-model-rejected-output-v1\0",
        &[schema.digest.as_bytes(), output],
    )
}

fn provider_idempotency_key(
    request: &ModelCallRequest,
    route: &EvaluatedRoute,
    repair: Option<&RepairContext>,
    shadow: bool,
) -> Result<ContentDigest> {
    let base = canonical_digest(
        b"contextdb-model-provider-operation-v1\0",
        &(
            &request.capability,
            &route.route.provider,
            &route.route.model_revision,
            &request.prompt,
            &request.output_schema,
            route.input.digest,
            route.decision.digest,
            request.max_output_tokens,
            shadow,
        ),
    )?;
    Ok(match repair {
        Some(repair) => digest_parts(
            b"contextdb-model-provider-repair-v1\0",
            &[
                base.as_bytes(),
                repair.rejected_output_digest.as_bytes(),
                &[repair_violation_code(repair.violation)],
            ],
        ),
        None => digest_parts(
            b"contextdb-model-provider-production-v1\0",
            &[base.as_bytes()],
        ),
    })
}

const fn repair_violation_code(violation: RepairViolation) -> u8 {
    match violation {
        RepairViolation::MalformedJson => 0,
        RepairViolation::StructuralSchema => 1,
        RepairViolation::SemanticSchema => 2,
        RepairViolation::OutputLimit => 3,
    }
}

fn repair_violation(error: &ModelRuntimeError) -> RepairViolation {
    match error {
        ModelRuntimeError::MalformedJson(_) => RepairViolation::MalformedJson,
        ModelRuntimeError::OutputTooLarge { .. } => RepairViolation::OutputLimit,
        ModelRuntimeError::SemanticViolation(_) => RepairViolation::SemanticSchema,
        _ => RepairViolation::StructuralSchema,
    }
}

const fn provider_status(kind: ProviderErrorKind) -> ModelCallStatus {
    match kind {
        ProviderErrorKind::Timeout => ModelCallStatus::Timeout,
        ProviderErrorKind::Unavailable | ProviderErrorKind::RateLimited => {
            ModelCallStatus::ProviderUnavailable
        }
        ProviderErrorKind::Refusal => ModelCallStatus::Refused,
        ProviderErrorKind::InvalidRequest => ModelCallStatus::InvalidRequest,
        ProviderErrorKind::Internal => ModelCallStatus::Failed,
    }
}
