//! Fail-closed adapters for pure preflight and canonical postflight validation.

use std::collections::BTreeSet;

use contextdb_continuity::{
    ContinuityError, PostflightRecord, PreflightEvaluator, PreflightReport, PreflightRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::{
    AuthenticatedRequestContext, ErrorCode, RuntimeRequest, RuntimeResponse, ServiceError,
    ServiceResult,
};

const MAX_RUNTIME_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_RUNTIME_JSON_DEPTH: usize = 64;
const MAX_RUNTIME_IDENTIFIER_BYTES: usize = 1024;
const MAX_RUNTIME_SCOPE_COUNT: usize = 4096;

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PostflightSubmissionV1 {
    preflight: PreflightRequest,
    record: PostflightRecord,
}

/// Validated canonical postflight bytes intended only as transient input to a
/// deployment-local keyed commitment. The bytes are zeroized when dropped and
/// must never be persisted, logged, or returned to the caller.
pub struct ValidatedPostflightSubmission {
    canonical_bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for ValidatedPostflightSubmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedPostflightSubmission")
            .field("canonical_bytes", &"[REDACTED]")
            .finish()
    }
}

impl ValidatedPostflightSubmission {
    /// Borrows the exact canonical submission bytes for keyed commitment.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// Computes and validates the canonical record digest for one otherwise exact
/// postflight record JSON value. This helper is intended for typed adapters and
/// fixtures; production persistence must not retain the returned unkeyed
/// digest because low-entropy outcomes remain dictionary-testable.
pub fn canonical_postflight_record_digest(record: &Value) -> ServiceResult<String> {
    let mut candidate = object(record)?.clone();
    candidate.insert("record_digest".to_owned(), Value::String("01".repeat(32)));
    let mut typed: PostflightRecord = serde_json::from_value(Value::Object(candidate))
        .map_err(|_| invalid_postflight_format())?;
    // Derive the digest from the exact canonical continuity tuple by allowing
    // the contract constructor to seal the already typed and bounded fields.
    typed = PostflightRecord::new(
        typed.action_id,
        typed.preflight_digest,
        typed.host_authorization,
        typed.plan_digest,
        typed.tool_results,
        typed.outcome,
        typed.verification,
        typed.artifacts,
        typed.follow_up_commitments,
        typed.completed_at,
    )
    .map_err(map_postflight_continuity_error)?;
    Ok(typed.record_digest.to_string())
}

/// Recomputes the canonical pure-preflight report for an exact preflight JSON
/// value. The result carries no authority and lets adapters avoid depending on
/// continuity implementation types merely to validate fixtures.
pub fn canonical_preflight_report(preflight: &Value) -> ServiceResult<Value> {
    let bytes = Zeroizing::new(serde_json::to_vec(preflight).map_err(|_| invalid_format())?);
    let request: PreflightRequest = serde_json::from_slice(&bytes).map_err(|_| invalid_format())?;
    let report = PreflightEvaluator::evaluate(&request).map_err(map_continuity_error)?;
    canonical_report_value(&report)
}

pub(crate) fn execute_preflight(request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
    validate_identifier(&request.operation_id)?;

    // The routing-safe scope manifest is checked before serialization, size
    // accounting, depth traversal, typed deserialization, or continuity
    // evaluation can inspect selected memory sections.
    validate_scope_binding(&request.payload, &request.context)?;

    let payload_bytes = serde_json::to_vec(&request.payload).map_err(|_| invalid_format())?;
    if payload_bytes.len() > MAX_RUNTIME_PAYLOAD_BYTES {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "runtime payload exceeds the 1 MiB service limit",
            false,
        ));
    }
    validate_json_depth(&request.payload)?;

    let continuity_request: PreflightRequest =
        serde_json::from_value(request.payload).map_err(|_| invalid_format())?;
    let report = PreflightEvaluator::evaluate(&continuity_request).map_err(map_continuity_error)?;
    canonical_report_value(&report).map(|payload| RuntimeResponse {
        operation_id: request.operation_id,
        payload,
    })
}

/// Authenticates, bounds, parses, and links one postflight caller assertion to
/// a freshly recomputed pure preflight report.
///
/// This function does not verify tool execution or outcome truth and performs
/// no persistence or semantic mutation. A durable production adapter may use
/// the returned bytes only to compute a secret-keyed, tenant-bound commitment.
pub fn validate_postflight_submission(
    request: &RuntimeRequest,
) -> ServiceResult<ValidatedPostflightSubmission> {
    // Capability and authentication must win before any payload field is read.
    crate::authenticated::require_capability(&request.context, crate::Capability::Runtime)?;
    validate_identifier(&request.operation_id)?;

    // Only the routing-safe scope manifest inside the submitted preflight is
    // inspected before protected payload size/depth/typed-schema processing.
    let root = object(&request.payload)?;
    let preflight = root
        .get("preflight")
        .ok_or_else(invalid_postflight_format)?;
    validate_scope_binding(preflight, &request.context)?;

    let payload_bytes = Zeroizing::new(
        serde_json::to_vec(&request.payload).map_err(|_| invalid_postflight_format())?,
    );
    if payload_bytes.len() > MAX_RUNTIME_PAYLOAD_BYTES {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "runtime postflight payload exceeds the 1 MiB service limit",
            false,
        ));
    }
    validate_json_depth(&request.payload)?;

    let submission: PostflightSubmissionV1 =
        serde_json::from_slice(&payload_bytes).map_err(|_| invalid_postflight_format())?;
    // Equality against the typed form closes unknown-field gaps in nested
    // tagged enums as well as the deny-unknown struct boundaries.
    let typed_value = serde_json::to_value(&submission).map_err(|_| invalid_postflight_format())?;
    if typed_value != request.payload {
        return Err(invalid_postflight_format());
    }

    let report =
        PreflightEvaluator::evaluate(&submission.preflight).map_err(map_continuity_error)?;
    let record_bytes = Zeroizing::new(
        submission
            .record
            .to_json()
            .map_err(map_postflight_continuity_error)?,
    );
    let canonical_record =
        PostflightRecord::from_json(&record_bytes).map_err(map_postflight_continuity_error)?;
    if canonical_record.action_id != report.action_id
        || canonical_record.preflight_digest != report.report_digest
        || canonical_record.host_authorization != report.host_authorization
    {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "runtime postflight does not match the recomputed preflight report",
            false,
        ));
    }

    let canonical_bytes = serde_json::to_vec(&submission).map_err(|_| {
        ServiceError::new(
            ErrorCode::IntegrityFailure,
            "runtime postflight canonical serialization failed",
            false,
        )
    })?;
    Ok(ValidatedPostflightSubmission {
        canonical_bytes: Zeroizing::new(canonical_bytes),
    })
}

fn canonical_report_value(report: &PreflightReport) -> ServiceResult<Value> {
    let bytes = report.to_json().map_err(map_continuity_error)?;
    let verified = PreflightReport::from_json(&bytes).map_err(map_continuity_error)?;
    if verified.grants_authority {
        return Err(ServiceError::new(
            ErrorCode::IntegrityFailure,
            "runtime preflight violated the no-authority invariant",
            false,
        ));
    }
    serde_json::from_slice(&bytes).map_err(|_| {
        ServiceError::new(
            ErrorCode::IntegrityFailure,
            "runtime preflight response is not canonical JSON",
            false,
        )
    })
}

fn validate_scope_binding(
    payload: &Value,
    context: &AuthenticatedRequestContext,
) -> ServiceResult<()> {
    let root = object(payload)?;
    let pack = object(root.get("context").ok_or_else(invalid_format)?)?;
    let manifest = object(pack.get("scope_manifest").ok_or_else(invalid_format)?)?;
    let workspace = bounded_string(manifest.get("workspace"))?;
    let subject = bounded_string(manifest.get("subject"))?;
    let scopes = bounded_string_set(manifest.get("scopes"))?;
    if bounded_string(manifest.get("purpose"))? != "action" {
        return Err(invalid_format());
    }
    if workspace != context.request.workspace_id
        || subject != context.request.subject_id
        || scopes != context.request.scopes
    {
        return Err(ServiceError::new(
            ErrorCode::PermissionDenied,
            "runtime ContextPack scope does not match the authenticated principal",
            false,
        )
        .with_context(
            Vec::new(),
            Some("runtime_scope_binding".to_owned()),
            Some("compile the ContextPack for the authenticated workspace and subject".to_owned()),
            None,
        ));
    }
    Ok(())
}

fn object(value: &Value) -> ServiceResult<&Map<String, Value>> {
    value.as_object().ok_or_else(invalid_format)
}

fn bounded_string(value: Option<&Value>) -> ServiceResult<&str> {
    let value = value.and_then(Value::as_str).ok_or_else(invalid_format)?;
    validate_identifier(value)?;
    Ok(value)
}

fn bounded_string_set(value: Option<&Value>) -> ServiceResult<BTreeSet<String>> {
    let values = value.and_then(Value::as_array).ok_or_else(invalid_format)?;
    if values.len() > MAX_RUNTIME_SCOPE_COUNT {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "runtime scope count exceeds the service limit",
            false,
        ));
    }
    let mut result = BTreeSet::new();
    for value in values {
        let value = bounded_string(Some(value))?;
        if !result.insert(value.to_owned()) {
            return Err(invalid_format());
        }
    }
    Ok(result)
}

fn validate_identifier(value: &str) -> ServiceResult<()> {
    if value.trim().is_empty() || value.len() > MAX_RUNTIME_IDENTIFIER_BYTES || value.contains('\0')
    {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "runtime request contains an invalid bounded identifier",
            false,
        ));
    }
    Ok(())
}

fn validate_json_depth(root: &Value) -> ServiceResult<()> {
    let mut pending = vec![(root, 1_usize)];
    while let Some((value, depth)) = pending.pop() {
        if depth > MAX_RUNTIME_JSON_DEPTH {
            return Err(ServiceError::new(
                ErrorCode::ResourceExhausted,
                "runtime payload exceeds the JSON depth limit",
                false,
            ));
        }
        match value {
            Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth.saturating_add(1))));
            }
            Value::Object(values) => {
                pending.extend(
                    values
                        .values()
                        .map(|value| (value, depth.saturating_add(1))),
                );
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn invalid_format() -> ServiceError {
    ServiceError::new(
        ErrorCode::FormatIncompatible,
        "runtime payload does not match the exact continuity preflight schema",
        false,
    )
}

fn invalid_postflight_format() -> ServiceError {
    ServiceError::new(
        ErrorCode::FormatIncompatible,
        "runtime payload does not match the exact postflight submission schema",
        false,
    )
}

fn map_continuity_error(error: ContinuityError) -> ServiceError {
    let (code, message) = match error {
        ContinuityError::PolicyDenied(_) => (
            ErrorCode::PermissionDenied,
            "continuity policy denied runtime preflight",
        ),
        ContinuityError::IdentityMismatch(_) => (
            ErrorCode::PermissionDenied,
            "continuity identity does not match runtime preflight",
        ),
        ContinuityError::IncompatibleRuntime(_) => (
            ErrorCode::FormatIncompatible,
            "runtime preflight is incompatible with the selected profile",
        ),
        ContinuityError::InvalidInput(_)
        | ContinuityError::InvalidTransition(_)
        | ContinuityError::Serialization(_)
        | ContinuityError::Dependency(_) => (
            ErrorCode::InvalidArgument,
            "continuity preflight input failed canonical validation",
        ),
    };
    ServiceError::new(code, message, false)
}

fn map_postflight_continuity_error(_error: ContinuityError) -> ServiceError {
    ServiceError::new(
        ErrorCode::InvalidArgument,
        "continuity postflight input failed canonical validation",
        false,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use crate::{
        AuthenticationEvidence, Capability, CognitiveMemoryService, ReferenceService,
        RequestContext, Sensitivity,
    };

    use super::*;

    #[test]
    fn validated_postflight_debug_is_redacted() {
        let value = ValidatedPostflightSubmission {
            canonical_bytes: Zeroizing::new(b"tool:debug-sentinel".to_vec()),
        };
        let debug = format!("{value:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("tool:debug-sentinel"));
    }

    fn context() -> AuthenticatedRequestContext {
        AuthenticatedRequestContext {
            request: RequestContext {
                request_id: "request:runtime".to_owned(),
                workspace_id: "workspace:a".to_owned(),
                subject_id: "subject:a".to_owned(),
                audiences: BTreeSet::from(["subject:a".to_owned()]),
                scopes: BTreeSet::from(["scope:a".to_owned()]),
                purpose: "runtime-test".to_owned(),
                clearance: Sensitivity::Private,
            },
            actor_id: "actor:a".to_owned(),
            agent_id: "agent:a".to_owned(),
            session_id: Some("session:a".to_owned()),
            capability_grants: BTreeSet::from([Capability::Runtime]),
            authentication: AuthenticationEvidence::AuthenticatedChannel {
                channel_id: "channel:a".to_owned(),
                peer_identity: "actor:a".to_owned(),
                binding_digest: "31".repeat(32),
            },
        }
    }

    #[test]
    fn mismatched_routing_identity_wins_before_protected_sections() {
        let first = json!({
            "context": {"scope_manifest": {
                "workspace": "workspace:other", "subject": "subject:a", "scopes": ["scope:a"],
                "purpose": "action"
            }, "sections": [{"secret": "tenant-a"}]}
        });
        let second = json!({
            "context": {"scope_manifest": {
                "workspace": "workspace:other", "subject": "subject:a", "scopes": ["scope:a"],
                "purpose": "action"
            }, "sections": [{"secret": {"entirely": "different"}}]}
        });
        let left = validate_scope_binding(&first, &context()).expect_err("mismatch");
        let right = validate_scope_binding(&second, &context()).expect_err("mismatch");
        assert_eq!(left, right);
        assert_eq!(left.code, ErrorCode::PermissionDenied);

        let mut deep = Value::String("x".repeat(MAX_RUNTIME_PAYLOAD_BYTES));
        for _ in 0..=MAX_RUNTIME_JSON_DEPTH {
            deep = json!([deep]);
        }
        let oversized_and_deep = json!({
            "context": {"scope_manifest": {
                "workspace": "workspace:other", "subject": "subject:a", "scopes": ["scope:a"],
                "purpose": "action"
            }, "sections": deep}
        });
        let request_error = execute_preflight(RuntimeRequest {
            context: context(),
            operation_id: "preflight:tenant-mismatch".to_owned(),
            payload: oversized_and_deep,
        })
        .expect_err("tenant mismatch must precede protected payload limits");
        assert_eq!(request_error, left);
    }

    #[test]
    fn routing_scope_set_is_exact_and_json_depth_is_bounded() {
        let payload = json!({"context": {"scope_manifest": {
            "workspace": "workspace:a", "subject": "subject:a", "scopes": ["scope:a", "scope:b"],
            "purpose": "action"
        }}});
        assert_eq!(
            validate_scope_binding(&payload, &context())
                .expect_err("scope expansion")
                .code,
            ErrorCode::PermissionDenied
        );
        let non_action = json!({"context": {"scope_manifest": {
            "workspace": "workspace:a", "subject": "subject:a", "scopes": ["scope:a"],
            "purpose": "conversation"
        }, "sections": [{"protected": "must-not-be-evaluated"}]}});
        assert_eq!(
            validate_scope_binding(&non_action, &context())
                .expect_err("non-action pack")
                .code,
            ErrorCode::FormatIncompatible
        );
        let mut deep = Value::Null;
        for _ in 0..=MAX_RUNTIME_JSON_DEPTH {
            deep = json!([deep]);
        }
        assert_eq!(
            validate_json_depth(&deep).expect_err("deep JSON").code,
            ErrorCode::ResourceExhausted
        );

        let invalid_operation = execute_preflight(RuntimeRequest {
            context: context(),
            operation_id: " ".to_owned(),
            payload: Value::Null,
        })
        .expect_err("blank operation identity");
        assert_eq!(invalid_operation.code, ErrorCode::InvalidArgument);

        let oversized = execute_preflight(RuntimeRequest {
            context: context(),
            operation_id: "preflight:oversized".to_owned(),
            payload: json!({
                "context": {"scope_manifest": {
                    "workspace": "workspace:a", "subject": "subject:a", "scopes": ["scope:a"],
                    "purpose": "action"
                }, "sections": [{"protected": "x".repeat(MAX_RUNTIME_PAYLOAD_BYTES)}]}
            }),
        })
        .expect_err("oversized payload");
        assert_eq!(oversized.code, ErrorCode::ResourceExhausted);
    }

    #[test]
    fn capability_denial_wins_before_any_protected_payload_shape() {
        let service = ReferenceService::new("runtime-auth-order", [0x71; 32]).expect("service");
        let mut caller = context();
        caller.capability_grants.clear();
        let call = |payload| {
            service
                .preflight(RuntimeRequest {
                    context: caller.clone(),
                    operation_id: "preflight:auth-order".to_owned(),
                    payload,
                })
                .expect_err("runtime capability must be required first")
        };
        let left = call(json!({"protected": "tenant-a"}));
        let right = call(json!({"protected": {"different": [1, 2, 3]}}));
        assert_eq!(left, right);
        assert_eq!(left.code, ErrorCode::Unauthorized);
    }
}
