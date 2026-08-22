use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use contextdb_core::{ContentDigest, LineageNode, Validate, WorkspaceId};
use serde::{Deserialize, Serialize};

use crate::types::{MAX_TEXT_BYTES, canonical_digest, digest_parts, validate_text};
use crate::{
    BasisPoints, CapabilityRoute, CurrencyCode, ExecutionLocality, LanguageTag, Modality,
    ModelCapability, ModelRuntimeError, ProviderId, RegionId, Result, Sensitivity,
};

const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// One cost-budget dimension from the RFC budget hierarchy.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BudgetScope {
    /// One model operation.
    Operation {
        /// Host operation identifier.
        id: String,
    },
    /// One session.
    Session {
        /// Host session identifier.
        id: String,
    },
    /// One agent runtime.
    Agent {
        /// Host agent identifier.
        id: String,
    },
    /// One workspace.
    Workspace {
        /// Workspace identity.
        id: WorkspaceId,
    },
    /// Day/month accounting bucket supplied by the host.
    Period {
        /// Workspace identity.
        workspace_id: WorkspaceId,
        /// Host-defined day/month bucket.
        bucket: String,
    },
    /// One capability.
    Capability {
        /// Constrained capability.
        capability: ModelCapability,
    },
    /// One provider.
    Provider {
        /// Constrained provider.
        provider: ProviderId,
    },
}

impl BudgetScope {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Operation { id } | Self::Session { id } | Self::Agent { id } => {
                validate_text(id, "budget_scope.id", 256)
            }
            Self::Period { bucket, .. } => validate_text(bucket, "budget_scope.bucket", 256),
            Self::Capability { capability } => capability.validate(),
            Self::Workspace { .. } | Self::Provider { .. } => Ok(()),
        }
    }
}

/// Remaining cost snapshot supplied by the host budget authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostBudget {
    /// Currency of every remaining micro-unit.
    pub currency: CurrencyCode,
    /// Remaining integer micro-units per active dimension.
    pub remaining_micros: BTreeMap<BudgetScope, u64>,
}

impl CostBudget {
    fn validate(&self) -> Result<()> {
        for scope in self.remaining_micros.keys() {
            scope.validate()?;
        }
        Ok(())
    }

    fn allows(&self, estimate: u64, provider: &ProviderId, capability: &ModelCapability) -> bool {
        self.remaining_micros.iter().all(|(scope, remaining)| {
            let relevant = match scope {
                BudgetScope::Provider {
                    provider: constrained,
                } => constrained == provider,
                BudgetScope::Capability {
                    capability: constrained,
                } => constrained == capability,
                _ => true,
            };
            !relevant || estimate <= *remaining
        })
    }
}

/// Effective data-handling, quality, latency, and cost constraints for a call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingPolicy {
    /// Bounded purpose required for audit and purpose limitation.
    pub purpose: String,
    /// External processing is explicitly allowed for this operation.
    pub allow_external: bool,
    /// Force deployment-local execution.
    pub local_only: bool,
    /// External processing consent was evaluated positively.
    pub external_consent: bool,
    /// Hosted provider allowlist; empty denies every hosted provider.
    pub provider_allowlist: BTreeSet<ProviderId>,
    /// Permitted hosted processing regions; empty accepts any declared region.
    pub allowed_regions: BTreeSet<RegionId>,
    /// Require a no-training provider promise.
    pub require_no_training: bool,
    /// Require a no-retention provider promise.
    pub require_no_retention: bool,
    /// External execution must use the separately supplied redacted payload.
    pub redact_before_external: bool,
    /// Maximum conservative route cost.
    pub max_estimated_cost_micros: u64,
    /// Maximum route tail-latency estimate.
    pub max_expected_p95_ms: u64,
    /// Minimum measured route quality.
    pub minimum_benchmark_score: BasisPoints,
    /// Minimum measured strict-schema reliability.
    pub minimum_schema_reliability: BasisPoints,
    /// Optional deterministic provider preference, first is strongest.
    pub preferred_providers: Vec<ProviderId>,
    /// Multi-dimensional host budget snapshot.
    pub cost_budget: CostBudget,
}

impl RoutingPolicy {
    /// Checks policy-local invariants.
    pub fn validate(&self) -> Result<()> {
        validate_text(&self.purpose, "routing_policy.purpose", MAX_TEXT_BYTES)?;
        if self.max_expected_p95_ms == 0 {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "routing_policy.max_expected_p95_ms",
                reason: "must be positive",
            });
        }
        let mut distinct = BTreeSet::new();
        for provider in &self.preferred_providers {
            if !distinct.insert(provider) {
                return Err(ModelRuntimeError::RegistryConflict(
                    "duplicate preferred provider".to_owned(),
                ));
            }
        }
        self.cost_budget.validate()
    }

    /// Computes a payload-free fingerprint of every routing constraint.
    ///
    /// Budget scopes are encoded as an ordered sequence rather than JSON map
    /// keys because structured enum keys are not representable as JSON object
    /// member names. `BTreeMap` iteration keeps the encoding deterministic.
    pub fn digest(&self) -> Result<ContentDigest> {
        self.validate()?;
        let budget_entries: Vec<_> = self.cost_budget.remaining_micros.iter().collect();
        canonical_digest(
            b"contextdb-model-routing-policy-v1\0",
            &(
                &self.purpose,
                self.allow_external,
                self.local_only,
                self.external_consent,
                &self.provider_allowlist,
                &self.allowed_regions,
                self.require_no_training,
                self.require_no_retention,
                self.redact_before_external,
                self.max_estimated_cost_micros,
                self.max_expected_p95_ms,
                self.minimum_benchmark_score,
                self.minimum_schema_reliability,
                &self.preferred_providers,
                &self.cost_budget.currency,
                budget_entries,
            ),
        )
    }
}

/// Input envelope kept out of `Debug` and audit payloads.
#[derive(Clone)]
pub struct ModelInput {
    primary: Arc<[u8]>,
    primary_digest: ContentDigest,
    external_redacted: Option<(Arc<[u8]>, ContentDigest, Sensitivity)>,
    /// Effective classification of the primary payload.
    pub sensitivity: Sensitivity,
    /// Input modality.
    pub modality: Modality,
    /// Optional language hint.
    pub language: Option<LanguageTag>,
    /// Token count produced by the selected tokenizer or a conservative host
    /// bound. Routing never estimates from character count.
    pub input_tokens: u32,
    /// Source lineage references, never source payload.
    pub source_refs: Vec<LineageNode>,
}

impl fmt::Debug for ModelInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelInput")
            .field("primary_digest", &self.primary_digest)
            .field("primary_bytes", &self.primary.len())
            .field(
                "has_external_redacted_payload",
                &self.external_redacted.is_some(),
            )
            .field("sensitivity", &self.sensitivity)
            .field("modality", &self.modality)
            .field("language", &self.language)
            .field("input_tokens", &self.input_tokens)
            .field("source_ref_count", &self.source_refs.len())
            .finish()
    }
}

impl ModelInput {
    /// Creates a bounded input envelope. The payload remains separated from the
    /// prompt instruction channel throughout gateway execution.
    pub fn new(
        payload: impl Into<Vec<u8>>,
        sensitivity: Sensitivity,
        modality: Modality,
        input_tokens: u32,
        source_refs: Vec<LineageNode>,
    ) -> Result<Self> {
        let payload = payload.into();
        if payload.len() > MAX_INPUT_BYTES || input_tokens == 0 {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "model_input",
                reason: "input byte/token budget is invalid",
            });
        }
        for source_ref in &source_refs {
            source_ref
                .validate()
                .map_err(|_| ModelRuntimeError::InvalidText {
                    field: "model_input.source_refs",
                    reason: "invalid lineage reference",
                })?;
        }
        let primary_digest = digest_parts(b"contextdb-model-input-v1\0", &[&payload]);
        Ok(Self {
            primary: Arc::from(payload),
            primary_digest,
            external_redacted: None,
            sensitivity,
            modality,
            language: None,
            input_tokens,
            source_refs,
        })
    }

    /// Supplies a separately minimized/redacted payload for hosted routes. The
    /// gateway never tries to invent semantic redaction from raw bytes.
    pub fn with_external_redacted(
        mut self,
        payload: impl Into<Vec<u8>>,
        sensitivity: Sensitivity,
    ) -> Result<Self> {
        let payload = payload.into();
        if payload.len() > MAX_INPUT_BYTES || sensitivity > self.sensitivity {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "model_input.external_redacted",
                reason: "redacted input is oversized or more sensitive than primary input",
            });
        }
        let digest = digest_parts(b"contextdb-model-redacted-input-v1\0", &[&payload]);
        self.external_redacted = Some((Arc::from(payload), digest, sensitivity));
        Ok(self)
    }

    /// Adds an evaluated language hint.
    #[must_use]
    pub fn with_language(mut self, language: LanguageTag) -> Self {
        self.language = Some(language);
        self
    }

    /// Digest of the protected primary input.
    #[must_use]
    pub const fn primary_digest(&self) -> ContentDigest {
        self.primary_digest
    }

    pub(crate) fn dedup_digest(&self) -> Result<ContentDigest> {
        canonical_digest(
            b"contextdb-model-input-envelope-v1\0",
            &(
                self.primary_digest,
                self.external_redacted
                    .as_ref()
                    .map(|(_, digest, sensitivity)| (*digest, *sensitivity)),
                self.sensitivity,
                self.modality,
                &self.language,
                self.input_tokens,
                &self.source_refs,
            ),
        )
    }

    pub(crate) fn protected_for_fallback(&self) -> PreparedModelInput {
        PreparedModelInput {
            payload: Arc::clone(&self.primary),
            digest: self.primary_digest,
            sensitivity: self.sensitivity,
            redacted: false,
            modality: self.modality,
            language: self.language.clone(),
            input_tokens: self.input_tokens,
            source_refs: self.source_refs.clone(),
        }
    }

    pub(crate) fn prepare(
        &self,
        route: &CapabilityRoute,
        policy: &RoutingPolicy,
    ) -> Result<PreparedModelInput> {
        if self.sensitivity == Sensitivity::Secret
            || !route.descriptor.input_modalities.contains(&self.modality)
        {
            return Err(ModelRuntimeError::PrivacyDenied);
        }
        if self.input_tokens > route.descriptor.max_input_tokens {
            return Err(ModelRuntimeError::PrivacyDenied);
        }
        let (payload, digest, sensitivity, redacted) = match route.descriptor.data_policy.locality {
            ExecutionLocality::Local => {
                if self.sensitivity > route.descriptor.data_policy.maximum_sensitivity {
                    return Err(ModelRuntimeError::PrivacyDenied);
                }
                (
                    Arc::clone(&self.primary),
                    self.primary_digest,
                    self.sensitivity,
                    false,
                )
            }
            ExecutionLocality::Hosted => {
                if policy.local_only
                    || !policy.allow_external
                    || !policy.external_consent
                    || !policy.provider_allowlist.contains(&route.provider)
                    || policy.require_no_training && !route.descriptor.data_policy.no_training
                    || policy.require_no_retention && !route.descriptor.data_policy.no_retention
                    || !policy.allowed_regions.is_empty()
                        && route
                            .descriptor
                            .data_policy
                            .region
                            .as_ref()
                            .is_none_or(|region| !policy.allowed_regions.contains(region))
                {
                    return Err(ModelRuntimeError::PrivacyDenied);
                }
                let requires_redaction =
                    policy.redact_before_external || self.sensitivity >= Sensitivity::Confidential;
                let selected = if requires_redaction {
                    let (payload, digest, sensitivity) = self
                        .external_redacted
                        .as_ref()
                        .ok_or(ModelRuntimeError::PrivacyDenied)?;
                    (Arc::clone(payload), *digest, *sensitivity, true)
                } else if let Some((payload, digest, sensitivity)) = &self.external_redacted {
                    (Arc::clone(payload), *digest, *sensitivity, true)
                } else {
                    (
                        Arc::clone(&self.primary),
                        self.primary_digest,
                        self.sensitivity,
                        false,
                    )
                };
                if selected.2 == Sensitivity::Secret
                    || selected.2 > route.descriptor.data_policy.maximum_sensitivity
                {
                    return Err(ModelRuntimeError::PrivacyDenied);
                }
                selected
            }
        };
        Ok(PreparedModelInput {
            payload,
            digest,
            sensitivity,
            redacted,
            modality: self.modality,
            language: self.language.clone(),
            input_tokens: self.input_tokens,
            source_refs: self.source_refs.clone(),
        })
    }
}

/// Payload selected after privacy routing. Its `Debug` representation remains
/// content-free; only provider adapters can read the bytes.
#[derive(Clone)]
pub struct PreparedModelInput {
    payload: Arc<[u8]>,
    /// Exact selected-input digest.
    pub digest: ContentDigest,
    /// Effective selected-input classification.
    pub sensitivity: Sensitivity,
    /// Whether the external-safe representation was selected.
    pub redacted: bool,
    /// Modality.
    pub modality: Modality,
    /// Language hint.
    pub language: Option<LanguageTag>,
    /// Token count bound.
    pub input_tokens: u32,
    /// Lineage references.
    pub source_refs: Vec<LineageNode>,
}

impl fmt::Debug for PreparedModelInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedModelInput")
            .field("digest", &self.digest)
            .field("bytes", &self.payload.len())
            .field("sensitivity", &self.sensitivity)
            .field("redacted", &self.redacted)
            .field("modality", &self.modality)
            .field("language", &self.language)
            .field("input_tokens", &self.input_tokens)
            .field("source_ref_count", &self.source_refs.len())
            .finish()
    }
}

impl PreparedModelInput {
    /// Returns selected minimized bytes to the isolated provider adapter.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.payload
    }
}

/// Safe policy decision metadata attached to every attempt audit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    /// Provider selected after filtering.
    pub provider: ProviderId,
    /// Local or hosted boundary.
    pub locality: ExecutionLocality,
    /// Whether redaction/minimization selected a separate payload.
    pub used_redacted_input: bool,
    /// Estimated cost reserved before execution.
    pub estimated_cost_micros: u64,
    /// Currency of the estimated cost and matching budget snapshot.
    pub estimated_cost_currency: CurrencyCode,
    /// Stable payload-free policy digest.
    pub digest: ContentDigest,
}

/// Route which passed policy, budget, capability, and quality checks.
#[derive(Clone, Debug)]
pub struct EvaluatedRoute {
    /// Registered descriptor.
    pub route: CapabilityRoute,
    /// Selected minimized input.
    pub input: PreparedModelInput,
    /// Auditable policy decision.
    pub decision: PolicyDecision,
}

/// Evaluates and deterministically orders registered routes.
pub fn evaluate_routes(
    routes: Vec<CapabilityRoute>,
    input: &ModelInput,
    capability: &ModelCapability,
    max_output_tokens: u32,
    policy: &RoutingPolicy,
) -> Result<Vec<EvaluatedRoute>> {
    policy.validate()?;
    let routing_policy_digest = policy.digest()?;
    let mut evaluated = Vec::new();
    for route in routes {
        let descriptor = &route.descriptor;
        if descriptor.capability != *capability
            || descriptor.latency_profile.p95_ms > policy.max_expected_p95_ms
            || descriptor.benchmark_score < policy.minimum_benchmark_score
            || descriptor.schema_reliability < policy.minimum_schema_reliability
            || input.language.as_ref().is_some_and(|language| {
                !descriptor.languages.is_empty() && !descriptor.languages.contains(language)
            })
        {
            continue;
        }
        if descriptor.expected_cost.currency != policy.cost_budget.currency {
            continue;
        }
        let estimate = descriptor
            .expected_cost
            .estimate(input.input_tokens, max_output_tokens)?;
        if estimate > policy.max_estimated_cost_micros
            || !policy
                .cost_budget
                .allows(estimate, &route.provider, capability)
        {
            continue;
        }
        let Ok(prepared) = input.prepare(&route, policy) else {
            continue;
        };
        let policy_digest = canonical_digest(
            b"contextdb-model-policy-decision-v1\0",
            &(
                &policy.purpose,
                &route.provider,
                descriptor.data_policy.locality,
                prepared.redacted,
                prepared.sensitivity,
                estimate,
                descriptor.output_schema.digest,
                routing_policy_digest,
            ),
        )?;
        evaluated.push(EvaluatedRoute {
            decision: PolicyDecision {
                provider: route.provider.clone(),
                locality: descriptor.data_policy.locality,
                used_redacted_input: prepared.redacted,
                estimated_cost_micros: estimate,
                estimated_cost_currency: descriptor.expected_cost.currency.clone(),
                digest: policy_digest,
            },
            route,
            input: prepared,
        });
    }
    evaluated.sort_by(|left, right| {
        let left_preference = preference_rank(policy, &left.route.provider);
        let right_preference = preference_rank(policy, &right.route.provider);
        left_preference
            .cmp(&right_preference)
            .then_with(|| {
                locality_rank(left.decision.locality).cmp(&locality_rank(right.decision.locality))
            })
            .then_with(|| {
                right
                    .route
                    .descriptor
                    .benchmark_score
                    .cmp(&left.route.descriptor.benchmark_score)
            })
            .then_with(|| {
                right
                    .route
                    .descriptor
                    .schema_reliability
                    .cmp(&left.route.descriptor.schema_reliability)
            })
            .then_with(|| {
                left.decision
                    .estimated_cost_micros
                    .cmp(&right.decision.estimated_cost_micros)
            })
            .then_with(|| {
                left.route
                    .descriptor
                    .latency_profile
                    .p95_ms
                    .cmp(&right.route.descriptor.latency_profile.p95_ms)
            })
            .then_with(|| left.route.provider.cmp(&right.route.provider))
            .then_with(|| left.route.model_revision.cmp(&right.route.model_revision))
    });
    Ok(evaluated)
}

fn preference_rank(policy: &RoutingPolicy, provider: &ProviderId) -> usize {
    policy
        .preferred_providers
        .iter()
        .position(|candidate| candidate == provider)
        .unwrap_or(usize::MAX)
}

const fn locality_rank(locality: ExecutionLocality) -> u8 {
    match locality {
        ExecutionLocality::Local => 0,
        ExecutionLocality::Hosted => 1,
    }
}
