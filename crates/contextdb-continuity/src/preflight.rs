//! Optional action-profile preflight and postflight contracts.

use std::collections::BTreeSet;

use contextdb_context::{BlockId, ContextPack, PackBlockKind, PackPurpose};
use contextdb_core::{
    ArtifactId, ContentDigest, ContextPackId, MemoryRef, NodeId, TimestampMicros,
};
use serde::{Deserialize, Serialize};

use crate::{
    ActionId, ContinuityError, Result, ToolId, canonical_digest, ensure_digest_nonzero,
    validate_text,
};

/// Host/tool authorization state, explicitly outside memory preflight.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostAuthorizationStatus {
    /// Tool/policy layer has not decided.
    Unchecked,
    /// Tool/policy layer independently authorized the action.
    Granted,
    /// Tool/policy layer denied the action.
    Denied,
}

/// Memory-derived guard; it may block but never grants tool authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryGuardDecision {
    /// No selected memory rule blocks the intent.
    AllowByMemoryPolicy,
    /// A selected boundary/constraint blocks the intent.
    DenyByMemoryPolicy,
    /// Uncertainty or conflict requires host/user review.
    NeedsReview,
}

/// Model-neutral action intent. It is data, never executable authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionIntent {
    /// Stable idempotency identity.
    pub id: ActionId,
    /// Plain-language bounded description.
    pub description: String,
    /// Tool requested by the host/agent, if any.
    pub requested_tool: Option<ToolId>,
    /// Host-declared external side-effect risk.
    pub mutates_external_state: bool,
    /// Deterministic digest of structured arguments; raw secrets are not copied.
    pub argument_digest: ContentDigest,
}

impl ActionIntent {
    /// Validates bounded text and non-placeholder argument digest.
    pub fn validate(&self) -> Result<()> {
        validate_text(&self.description, "action description", 4096)?;
        ensure_digest_nonzero(self.argument_digest, "action argument digest")
    }
}

/// Preflight request over one already policy-safe action ContextPack.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightRequest {
    /// Intended action.
    pub action: ActionIntent,
    /// ContextPack compiled for action purpose.
    pub context: ContextPack,
    /// Independent host authorization status at evaluation time.
    pub host_authorization: HostAuthorizationStatus,
    /// Required verification labels declared by the caller.
    pub required_verifications: BTreeSet<String>,
}

/// Explainable memory guard and selected preflight categories.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightReport {
    /// Action being evaluated.
    pub action_id: ActionId,
    /// Exact ContextPack identity and digest.
    pub context_pack_id: ContextPackId,
    /// Lowercase digest of canonical ContextPack Protobuf bytes.
    pub context_pack_digest: String,
    /// Memory-only decision.
    pub memory_guard: MemoryGuardDecision,
    /// Independent host/tool authorization copied for clarity.
    pub host_authorization: HostAuthorizationStatus,
    /// Always false: preflight never grants authority.
    pub grants_authority: bool,
    /// Selected boundary/constraint block IDs.
    pub constraints: Vec<BlockId>,
    /// Selected previous decision block IDs.
    pub previous_decisions: Vec<BlockId>,
    /// Selected procedure block IDs.
    pub procedures: Vec<BlockId>,
    /// Selected preference block IDs.
    pub preferences: Vec<BlockId>,
    /// Selected unknown/conflict block IDs requiring review.
    pub unresolved: Vec<BlockId>,
    /// Exact verification requirements.
    pub required_verifications: BTreeSet<String>,
    /// Payload-free canonical report digest.
    pub report_digest: ContentDigest,
}

impl PreflightReport {
    /// Revalidates canonical ordering and the no-authorization invariant.
    pub fn validate(&self) -> Result<()> {
        if self.grants_authority {
            return Err(ContinuityError::InvalidInput(
                "memory preflight must never grant tool authority".to_owned(),
            ));
        }
        for (name, values) in [
            ("constraints", &self.constraints),
            ("decisions", &self.previous_decisions),
            ("procedures", &self.procedures),
            ("preferences", &self.preferences),
            ("unresolved", &self.unresolved),
        ] {
            if values.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(ContinuityError::InvalidInput(format!(
                    "preflight {name} are not in strict canonical order"
                )));
            }
        }
        if self.context_pack_digest.len() != 64
            || !self
                .context_pack_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ContinuityError::InvalidInput(
                "preflight ContextPack digest is not canonical hexadecimal".to_owned(),
            ));
        }
        for verification in &self.required_verifications {
            validate_text(verification, "preflight verification", 512)?;
        }
        if self.report_digest != self.compute_digest()? {
            return Err(ContinuityError::InvalidInput(
                "preflight report digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Emits compact canonical JSON after complete validation.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| ContinuityError::Serialization(error.to_string()))
    }

    /// Parses canonical JSON and rejects tampering or alternate encodings.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ContinuityError::Serialization(error.to_string()))?;
        value.validate()?;
        if value.to_json()? != bytes {
            return Err(ContinuityError::Serialization(
                "preflight report JSON is not canonical".to_owned(),
            ));
        }
        Ok(value)
    }

    fn compute_digest(&self) -> Result<ContentDigest> {
        canonical_digest(&(
            &self.action_id,
            self.context_pack_id,
            &self.context_pack_digest,
            self.memory_guard,
            self.host_authorization,
            self.grants_authority,
            &self.constraints,
            &self.previous_decisions,
            &self.procedures,
            &self.preferences,
            &self.unresolved,
            &self.required_verifications,
        ))
    }
}

/// Deterministic action-profile preflight.
#[derive(Clone, Copy, Debug, Default)]
pub struct PreflightEvaluator;

impl PreflightEvaluator {
    /// Evaluates memory constraints without issuing external authorization.
    pub fn evaluate(request: &PreflightRequest) -> Result<PreflightReport> {
        request.action.validate()?;
        request
            .context
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        if request.context.purpose != PackPurpose::Action {
            return Err(ContinuityError::InvalidInput(
                "preflight requires an action-purpose ContextPack".to_owned(),
            ));
        }
        for verification in &request.required_verifications {
            validate_text(verification, "preflight verification", 512)?;
        }
        let collect = |kinds: &[PackBlockKind]| -> Vec<BlockId> {
            request
                .context
                .sections
                .iter()
                .filter(|block| kinds.contains(&block.kind))
                .map(|block| block.id.clone())
                .collect()
        };
        let constraints = collect(&[PackBlockKind::Boundary, PackBlockKind::Constraint]);
        let previous_decisions = collect(&[PackBlockKind::Decision]);
        let procedures = collect(&[PackBlockKind::Procedure]);
        let preferences = collect(&[PackBlockKind::Preference]);
        let unresolved = collect(&[PackBlockKind::Conflict, PackBlockKind::Unknown]);
        let denied = request.context.sections.iter().any(|block| {
            matches!(
                block.kind,
                PackBlockKind::Boundary | PackBlockKind::Constraint
            ) && (block
                .representation
                .fields
                .get("decision")
                .map(String::as_str)
                == Some("deny")
                || block
                    .representation
                    .fields
                    .get("prohibited")
                    .map(String::as_str)
                    == Some("true"))
        });
        let memory_guard = if denied {
            MemoryGuardDecision::DenyByMemoryPolicy
        } else if !unresolved.is_empty() {
            MemoryGuardDecision::NeedsReview
        } else {
            MemoryGuardDecision::AllowByMemoryPolicy
        };
        let mut report = PreflightReport {
            action_id: request.action.id.clone(),
            context_pack_id: request.context.id,
            context_pack_digest: contextdb_context::CanonicalSerializer::digest(&request.context)
                .map_err(|error| ContinuityError::Dependency(error.to_string()))?,
            memory_guard,
            host_authorization: request.host_authorization,
            grants_authority: false,
            constraints,
            previous_decisions,
            procedures,
            preferences,
            unresolved,
            required_verifications: request.required_verifications.clone(),
            report_digest: ContentDigest::from_bytes([0_u8; 32]),
        };
        report.report_digest = report.compute_digest()?;
        report.validate()?;
        Ok(report)
    }
}

/// Verification outcome recorded after an action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VerificationOutcome {
    /// Deterministic or externally evidenced success.
    Passed {
        /// Stable evidence/memory references supporting the verification.
        evidence: BTreeSet<MemoryRef>,
    },
    /// Verification ran and found a mismatch.
    Failed {
        /// Non-secret bounded mismatch reason.
        reason: String,
    },
    /// Verification was unavailable; never treated as success.
    Unknown {
        /// Non-secret bounded explanation of what remains unknown.
        reason: String,
    },
}

/// Outcome of the attempted action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ActionOutcome {
    /// Requested side effect completed.
    Succeeded,
    /// Action completed only partially.
    Partial {
        /// Non-secret bounded partial-outcome reason.
        reason: String,
    },
    /// Action did not complete.
    Failed {
        /// Non-secret bounded failure reason.
        reason: String,
    },
    /// No action was attempted.
    NotRun {
        /// Non-secret bounded reason the action was not run.
        reason: String,
    },
}

/// Untrusted tool result referenced by digest, never converted to instructions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResultRef {
    /// Tool adapter that produced the result.
    pub tool: ToolId,
    /// Digest of the exact raw result artifact.
    pub digest: ContentDigest,
    /// True by invariant; serialized to make the boundary visible.
    pub untrusted: bool,
}

/// Durable postflight linkage; semantic promotion remains proposal-only upstream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostflightRecord {
    /// Stable action identity.
    pub action_id: ActionId,
    /// Preflight report that governed memory-side constraints.
    pub preflight_digest: ContentDigest,
    /// Host authorization actually used.
    pub host_authorization: HostAuthorizationStatus,
    /// Digest of the actual plan executed.
    pub plan_digest: ContentDigest,
    /// Canonically sorted untrusted tool result references.
    pub tool_results: Vec<ToolResultRef>,
    /// Actual outcome.
    pub outcome: ActionOutcome,
    /// Explicit verification state.
    pub verification: VerificationOutcome,
    /// New artifacts created by the action.
    pub artifacts: BTreeSet<ArtifactId>,
    /// Follow-up commitments proposed by postflight.
    pub follow_up_commitments: BTreeSet<NodeId>,
    /// Host-supplied completion time.
    pub completed_at: TimestampMicros,
    /// Canonical payload-free record digest.
    pub record_digest: ContentDigest,
}

impl PostflightRecord {
    /// Seals and validates a postflight record.
    #[allow(clippy::too_many_arguments, reason = "postflight axes remain explicit")]
    pub fn new(
        action_id: ActionId,
        preflight_digest: ContentDigest,
        host_authorization: HostAuthorizationStatus,
        plan_digest: ContentDigest,
        mut tool_results: Vec<ToolResultRef>,
        outcome: ActionOutcome,
        verification: VerificationOutcome,
        artifacts: BTreeSet<ArtifactId>,
        follow_up_commitments: BTreeSet<NodeId>,
        completed_at: TimestampMicros,
    ) -> Result<Self> {
        tool_results
            .sort_by(|left, right| (&left.tool, left.digest).cmp(&(&right.tool, right.digest)));
        let mut value = Self {
            action_id,
            preflight_digest,
            host_authorization,
            plan_digest,
            tool_results,
            outcome,
            verification,
            artifacts,
            follow_up_commitments,
            completed_at,
            record_digest: ContentDigest::from_bytes([0_u8; 32]),
        };
        value.record_digest = value.compute_digest()?;
        value.validate()?;
        Ok(value)
    }

    /// Rejects fake trusted tool output, false success, duplicate refs, and tampering.
    pub fn validate(&self) -> Result<()> {
        ensure_digest_nonzero(self.preflight_digest, "postflight preflight digest")?;
        ensure_digest_nonzero(self.plan_digest, "postflight plan digest")?;
        if self
            .tool_results
            .windows(2)
            .any(|pair| (&pair[0].tool, pair[0].digest) >= (&pair[1].tool, pair[1].digest))
        {
            return Err(ContinuityError::InvalidInput(
                "postflight tool results are not in strict canonical order".to_owned(),
            ));
        }
        for result in &self.tool_results {
            ensure_digest_nonzero(result.digest, "tool result digest")?;
            if !result.untrusted {
                return Err(ContinuityError::InvalidInput(
                    "tool result cannot gain trusted instruction status".to_owned(),
                ));
            }
        }
        if matches!(self.outcome, ActionOutcome::Succeeded)
            && self.host_authorization != HostAuthorizationStatus::Granted
        {
            return Err(ContinuityError::InvalidInput(
                "successful external action lacks independent host authorization".to_owned(),
            ));
        }
        for reason in match &self.outcome {
            ActionOutcome::Partial { reason }
            | ActionOutcome::Failed { reason }
            | ActionOutcome::NotRun { reason } => Some(reason),
            ActionOutcome::Succeeded => None,
        }
        .into_iter()
        .chain(match &self.verification {
            VerificationOutcome::Failed { reason } | VerificationOutcome::Unknown { reason } => {
                Some(reason)
            }
            VerificationOutcome::Passed { .. } => None,
        }) {
            validate_text(reason, "postflight outcome reason", 2048)?;
        }
        if self.record_digest != self.compute_digest()? {
            return Err(ContinuityError::InvalidInput(
                "postflight record digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Emits compact canonical JSON after validating action, tool, and verification axes.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| ContinuityError::Serialization(error.to_string()))
    }

    /// Parses canonical JSON and rejects tampering or alternate encodings.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ContinuityError::Serialization(error.to_string()))?;
        value.validate()?;
        if value.to_json()? != bytes {
            return Err(ContinuityError::Serialization(
                "postflight record JSON is not canonical".to_owned(),
            ));
        }
        Ok(value)
    }

    fn compute_digest(&self) -> Result<ContentDigest> {
        canonical_digest(&(
            &self.action_id,
            self.preflight_digest,
            self.host_authorization,
            self.plan_digest,
            &self.tool_results,
            &self.outcome,
            &self.verification,
            &self.artifacts,
            &self.follow_up_commitments,
            self.completed_at,
        ))
    }
}
