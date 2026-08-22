use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AccessPolicy, AuthenticatedRequestContext, Capability, CognitiveMemoryService, ErrorCode,
    ObserveRequest, ObserveResponse, RecallRequest, RecallResponse, ServiceError, ServiceResult,
};

const MAX_HIGH_LEVEL_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONTROL_JSON_BYTES: usize = 64 * 1024;
const MAX_REFERENCES: usize = 1_024;
const MAX_CONTROL_POLICY_VALUES: usize = 4_096;
const CONTROL_SCHEMA_VERSION: u16 = 1;

/// A policy-first high-level write which is compiled into one canonical
/// observation. It deliberately exposes semantic intent rather than graph
/// nodes, edges, dense identifiers, or storage layout.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighLevelWriteRequest {
    /// Fully attributed caller and verified authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Caller retry key, scoped by workspace, actor, and named operation.
    pub idempotency_key: String,
    /// Memory subject whose continuity is being changed.
    pub target_subject_id: String,
    /// Explicit conversation session binding when the operation is session-scoped.
    pub session_id: Option<String>,
    /// Stable high-level object identity, such as a session or artifact ID.
    pub logical_id: String,
    /// Authorization label stored separately from semantic content.
    pub access: AccessPolicy,
    /// Operation-specific high-level data; never a raw graph mutation.
    pub payload: serde_json::Value,
    /// Stable semantic references, such as an episode or artifact identity.
    #[serde(default)]
    pub references: BTreeSet<String>,
}

/// A bounded high-level recall request compiled into canonical recall.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighLevelQueryRequest {
    /// Fully attributed caller and verified authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Memory subject whose authorized memory is being queried.
    pub target_subject_id: String,
    /// Structured textual cue; adapters never interpret it as a command.
    pub cue: String,
    /// Strict page size, inherited by canonical recall.
    pub page_size: u32,
    /// Optional exact semantic snapshot.
    pub at_commit: Option<u64>,
    /// Optional operation- and snapshot-bound continuation.
    pub continuation: Option<String>,
}

/// A high-level memory, role, sharing, or lineage control request.
///
/// Controls carry no graph document. A profile either translates the intent
/// atomically or returns a typed gap; it must never pretend that recording the
/// command changed the governed object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighLevelControlRequest {
    /// Fully attributed caller and verified authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Caller retry key, scoped by workspace, actor, and named operation.
    pub idempotency_key: String,
    /// Memory subject that owns the governed object.
    pub target_subject_id: String,
    /// Stable memory, role, shared-memory, runtime, or lineage identity.
    pub target_id: String,
    /// High-level desired state, not a raw graph patch.
    pub parameters: serde_json::Value,
}

/// A subject-scoped portable transfer request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighLevelTransferRequest {
    /// Fully attributed caller and verified authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Caller retry key. Exports may use it as an operation correlation key.
    pub idempotency_key: String,
    /// Exact subject whose authorized logical memory is transferred.
    pub target_subject_id: String,
    /// Portable subject archive format, empty only for export negotiation.
    pub format: String,
    /// Canonical subject archive bytes for import; empty for export.
    #[serde(default)]
    pub bytes: Vec<u8>,
    /// Lowercase BLAKE3 digest for import; empty for export.
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SuppressParametersV1 {
    pub(crate) schema_version: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChangeAudienceParametersV1 {
    pub(crate) schema_version: u16,
    pub(crate) audiences: BTreeSet<String>,
    pub(crate) audience_purpose_grants: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublishSharedParametersV1 {
    pub(crate) schema_version: u16,
    pub(crate) shared_audience_id: String,
    pub(crate) purposes: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevokeSharedParametersV1 {
    pub(crate) schema_version: u16,
    pub(crate) shared_audience_id: String,
}

/// Durable high-level write receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighLevelMutationResponse {
    /// Canonical RFC operation name.
    pub operation: String,
    /// Stable high-level logical identity accepted by the operation.
    pub logical_id: String,
    /// Policy decision made before content entered the generic operation.
    pub policy_result: HighLevelPolicyResult,
    /// Semantic projection state. Durable capture does not claim synchronous
    /// graph publication.
    pub semantic_status: HighLevelSemanticStatus,
    /// Canonical durable observation receipt.
    pub receipt: ObserveResponse,
}

/// High-level policy result vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighLevelPolicyResult {
    /// Authentication, capability, subject, workspace, and access checks passed.
    Accepted,
}

/// High-level semantic publication state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighLevelSemanticStatus {
    /// Source capture is durable; semantic projection remains asynchronous.
    Pending,
}

pub(crate) fn execute_write<S: CognitiveMemoryService + ?Sized>(
    service: &S,
    request: HighLevelWriteRequest,
    operation: &'static str,
    session_bound: bool,
) -> ServiceResult<HighLevelMutationResponse> {
    crate::authenticated::require_capability(&request.context, Capability::Observe)?;
    validate_subject_binding(&request.context, &request.target_subject_id)?;
    validate_identifier(&request.idempotency_key)?;
    validate_identifier(&request.logical_id)?;
    validate_access_binding(&request)?;
    validate_references(&request.references)?;
    validate_payload(&request.payload)?;
    if session_bound
        && (request.session_id.is_none() || request.context.session_id != request.session_id)
    {
        return Err(ServiceError::new(
            ErrorCode::PermissionDenied,
            "conversation operation is not bound to the authenticated session",
            false,
        ));
    }

    let scoped_key = scoped_idempotency_key(&request.context, operation, &request.idempotency_key)?;
    let observation_id = scoped_observation_id(&request.context, operation, &request.logical_id)?;
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "contextdb.high_level.operation".to_owned(),
        serde_json::Value::String(operation.to_owned()),
    );
    metadata.insert(
        "contextdb.high_level.target_subject_id".to_owned(),
        serde_json::Value::String(request.target_subject_id.clone()),
    );
    metadata.insert(
        "contextdb.high_level.logical_id".to_owned(),
        serde_json::Value::String(request.logical_id.clone()),
    );
    metadata.insert(
        "contextdb.high_level.reference_count".to_owned(),
        serde_json::Value::Number(request.references.len().into()),
    );
    let content = serde_json::json!({
        "schema": "contextdb.high_level.v1",
        "operation": operation,
        "target_subject_id": request.target_subject_id,
        "session_id": request.session_id,
        "logical_id": request.logical_id,
        "references": request.references,
        "payload": request.payload,
    });
    let logical_id = content
        .get("logical_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let receipt = service.observe(ObserveRequest {
        context: request.context.request,
        idempotency_key: scoped_key,
        observation_id,
        metadata,
        content,
        access: request.access,
    })?;
    Ok(HighLevelMutationResponse {
        operation: operation.to_owned(),
        logical_id,
        policy_result: HighLevelPolicyResult::Accepted,
        semantic_status: HighLevelSemanticStatus::Pending,
        receipt,
    })
}

pub(crate) fn execute_query<S: CognitiveMemoryService + ?Sized>(
    service: &S,
    request: HighLevelQueryRequest,
    operation: &'static str,
    require_session: bool,
) -> ServiceResult<RecallResponse> {
    crate::authenticated::require_capability(&request.context, Capability::Recall)?;
    validate_subject_binding(&request.context, &request.target_subject_id)?;
    validate_identifier(&request.cue)?;
    if require_session && request.context.session_id.is_none() {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "conversation query requires an authenticated session",
            false,
        ));
    }
    let query = format!(
        "contextdb-operation:{operation}\ncontextdb-subject:{}\n{}",
        request.target_subject_id, request.cue
    );
    service.recall(RecallRequest {
        context: request.context.request,
        query,
        page_size: request.page_size,
        at_commit: request.at_commit,
        continuation: request.continuation,
    })
}

pub(crate) fn unsupported_control(
    request: &HighLevelControlRequest,
    capability: Capability,
    operation: &'static str,
    message: &'static str,
) -> ServiceResult<crate::MutationResponse> {
    crate::authenticated::require_capability(&request.context, capability)?;
    validate_subject_binding(&request.context, &request.target_subject_id)?;
    validate_identifier(&request.idempotency_key)?;
    validate_identifier(&request.target_id)?;
    Err(typed_gap(operation, message))
}

pub(crate) fn authorize_control_envelope(
    request: &HighLevelControlRequest,
    capability: Capability,
) -> ServiceResult<()> {
    crate::authenticated::require_capability(&request.context, capability)?;
    validate_subject_binding(&request.context, &request.target_subject_id)?;
    validate_identifier(&request.idempotency_key)?;
    validate_identifier(&request.target_id)
}

pub(crate) fn parse_suppress_parameters(
    value: &serde_json::Value,
) -> ServiceResult<SuppressParametersV1> {
    parse_control_parameters(value, "Suppress")
}

pub(crate) fn parse_change_audience_parameters(
    value: &serde_json::Value,
) -> ServiceResult<ChangeAudienceParametersV1> {
    let parameters: ChangeAudienceParametersV1 = parse_control_parameters(value, "ChangeAudience")?;
    validate_control_set(&parameters.audiences)?;
    if parameters.audience_purpose_grants.len() > MAX_CONTROL_POLICY_VALUES {
        return Err(control_limit_error());
    }
    for (audience, purposes) in &parameters.audience_purpose_grants {
        validate_identifier(audience)?;
        validate_control_set(purposes)?;
        if purposes.is_empty() {
            return Err(control_format_error("ChangeAudience"));
        }
    }
    Ok(parameters)
}

pub(crate) fn parse_publish_shared_parameters(
    value: &serde_json::Value,
) -> ServiceResult<PublishSharedParametersV1> {
    let parameters: PublishSharedParametersV1 =
        parse_control_parameters(value, "PublishToSharedMemory")?;
    validate_identifier(&parameters.shared_audience_id)?;
    validate_control_set(&parameters.purposes)?;
    if parameters.purposes.is_empty() {
        return Err(control_format_error("PublishToSharedMemory"));
    }
    Ok(parameters)
}

pub(crate) fn parse_revoke_shared_parameters(
    value: &serde_json::Value,
) -> ServiceResult<RevokeSharedParametersV1> {
    let parameters: RevokeSharedParametersV1 =
        parse_control_parameters(value, "RevokeSharedMemory")?;
    validate_identifier(&parameters.shared_audience_id)?;
    Ok(parameters)
}

fn parse_control_parameters<T: serde::de::DeserializeOwned>(
    value: &serde_json::Value,
    operation: &'static str,
) -> ServiceResult<T> {
    let bytes = serde_json::to_vec(value).map_err(|_| control_format_error(operation))?;
    if bytes.len() > MAX_CONTROL_JSON_BYTES {
        return Err(control_limit_error());
    }
    let parameters: T =
        serde_json::from_slice(&bytes).map_err(|_| control_format_error(operation))?;
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64);
    if schema_version != Some(u64::from(CONTROL_SCHEMA_VERSION)) {
        return Err(control_format_error(operation));
    }
    Ok(parameters)
}

fn validate_control_set(values: &BTreeSet<String>) -> ServiceResult<()> {
    if values.len() > MAX_CONTROL_POLICY_VALUES {
        return Err(control_limit_error());
    }
    for value in values {
        validate_identifier(value)?;
    }
    Ok(())
}

fn control_format_error(operation: &'static str) -> ServiceError {
    ServiceError::new(
        ErrorCode::FormatIncompatible,
        format!("{operation} parameters do not match the exact v1 control schema"),
        false,
    )
}

fn control_limit_error() -> ServiceError {
    ServiceError::new(
        ErrorCode::ResourceExhausted,
        "semantic-control parameters exceed the v1 bound",
        false,
    )
}

pub(crate) fn unsupported_transfer<T>(
    request: &HighLevelTransferRequest,
    capability: Capability,
    operation: &'static str,
    message: &'static str,
) -> ServiceResult<T> {
    crate::authenticated::require_capability(&request.context, capability)?;
    validate_subject_binding(&request.context, &request.target_subject_id)?;
    validate_identifier(&request.idempotency_key)?;
    Err(typed_gap(operation, message))
}

pub(crate) fn unsupported_write<T>(
    request: &HighLevelWriteRequest,
    capability: Capability,
    operation: &'static str,
    message: &'static str,
) -> ServiceResult<T> {
    crate::authenticated::require_capability(&request.context, capability)?;
    validate_subject_binding(&request.context, &request.target_subject_id)?;
    validate_identifier(&request.idempotency_key)?;
    validate_identifier(&request.logical_id)?;
    Err(typed_gap(operation, message))
}

fn validate_subject_binding(
    context: &AuthenticatedRequestContext,
    target_subject_id: &str,
) -> ServiceResult<()> {
    validate_identifier(target_subject_id)?;
    if context.request.subject_id != target_subject_id {
        return Err(ServiceError::new(
            ErrorCode::PermissionDenied,
            "high-level operation target is not the authenticated memory subject",
            false,
        )
        .with_context(
            Vec::new(),
            Some("subject_binding".to_owned()),
            Some("authenticate directly for the target memory subject".to_owned()),
            None,
        ));
    }
    Ok(())
}

fn validate_access_binding(request: &HighLevelWriteRequest) -> ServiceResult<()> {
    if request.access.workspace_id != request.context.request.workspace_id
        || !request.access.owners.contains(&request.target_subject_id)
        || !request
            .access
            .owners
            .is_subset(&request.context.request.audiences)
        || !request
            .access
            .audience
            .is_subset(&request.context.request.audiences)
        || !request
            .access
            .scopes
            .is_subset(&request.context.request.scopes)
        || request.access.sensitivity > request.context.request.clearance
        || request.access.consent != crate::Consent::Granted
        || request
            .access
            .purposes
            .iter()
            .any(|purpose| purpose != &request.context.request.purpose)
        || request
            .access
            .audience_purpose_grants
            .iter()
            .any(|(audience, purposes)| {
                !request.access.audience.contains(audience)
                    || purposes
                        .iter()
                        .any(|purpose| purpose != &request.context.request.purpose)
            })
    {
        return Err(ServiceError::new(
            ErrorCode::PermissionDenied,
            "high-level write policy exceeds the authenticated subject or workspace grant",
            false,
        )
        .with_context(
            Vec::new(),
            Some("high_level_access_binding".to_owned()),
            Some("use the authenticated workspace, owner, and granted scopes".to_owned()),
            None,
        ));
    }
    Ok(())
}

fn validate_references(references: &BTreeSet<String>) -> ServiceResult<()> {
    if references.len() > MAX_REFERENCES {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "high-level reference count exceeds the service limit",
            false,
        ));
    }
    for reference in references {
        validate_identifier(reference)?;
    }
    Ok(())
}

fn validate_payload(payload: &serde_json::Value) -> ServiceResult<()> {
    let size = serde_json::to_vec(payload)
        .map_err(|_| {
            ServiceError::new(
                ErrorCode::InvalidArgument,
                "high-level payload is not canonical JSON",
                false,
            )
        })?
        .len();
    if size > MAX_HIGH_LEVEL_JSON_BYTES {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "high-level payload exceeds the 8 MiB semantic limit",
            false,
        ));
    }
    Ok(())
}

fn validate_identifier(value: &str) -> ServiceResult<()> {
    if value.trim().is_empty() || value.len() > 1_024 || value.contains('\0') {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "high-level request contains an invalid bounded identifier",
            false,
        ));
    }
    Ok(())
}

fn scoped_idempotency_key(
    context: &AuthenticatedRequestContext,
    operation: &str,
    caller_key: &str,
) -> ServiceResult<String> {
    #[derive(Serialize)]
    struct Binding<'a> {
        domain: &'static str,
        workspace_id: &'a str,
        actor_id: &'a str,
        agent_id: &'a str,
        subject_id: &'a str,
        audiences: &'a BTreeSet<String>,
        scopes: &'a BTreeSet<String>,
        purpose: &'a str,
        session_id: &'a Option<String>,
        operation: &'a str,
        caller_key: &'a str,
    }
    let bytes = serde_json::to_vec(&Binding {
        domain: "contextdb/high-level-idempotency/v1",
        workspace_id: &context.request.workspace_id,
        actor_id: &context.actor_id,
        agent_id: &context.agent_id,
        subject_id: &context.request.subject_id,
        audiences: &context.request.audiences,
        scopes: &context.request.scopes,
        purpose: &context.request.purpose,
        session_id: &context.session_id,
        operation,
        caller_key,
    })
    .map_err(|_| {
        ServiceError::new(
            ErrorCode::IntegrityFailure,
            "high-level idempotency binding could not be serialized",
            false,
        )
    })?;
    Ok(format!(
        "high-level-v1:{operation}:{}",
        blake3::hash(&bytes).to_hex()
    ))
}

fn scoped_observation_id(
    context: &AuthenticatedRequestContext,
    operation: &str,
    logical_id: &str,
) -> ServiceResult<String> {
    #[derive(Serialize)]
    struct Binding<'a> {
        domain: &'static str,
        workspace_id: &'a str,
        actor_id: &'a str,
        agent_id: &'a str,
        subject_id: &'a str,
        audiences: &'a BTreeSet<String>,
        scopes: &'a BTreeSet<String>,
        purpose: &'a str,
        session_id: &'a Option<String>,
        operation: &'a str,
        logical_id: &'a str,
    }
    let bytes = serde_json::to_vec(&Binding {
        domain: "contextdb/high-level-observation-identity/v1",
        workspace_id: &context.request.workspace_id,
        actor_id: &context.actor_id,
        agent_id: &context.agent_id,
        subject_id: &context.request.subject_id,
        audiences: &context.request.audiences,
        scopes: &context.request.scopes,
        purpose: &context.request.purpose,
        session_id: &context.session_id,
        operation,
        logical_id,
    })
    .map_err(|_| {
        ServiceError::new(
            ErrorCode::IntegrityFailure,
            "high-level observation identity could not be serialized",
            false,
        )
    })?;
    Ok(format!("high-level-v1:{}", blake3::hash(&bytes).to_hex()))
}

fn typed_gap(operation: &'static str, message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::Unsupported, message, false).with_context(
        Vec::new(),
        Some(format!("reference_profile:{operation}")),
        Some("select a profile with the required atomic executor".to_owned()),
        None,
    )
}
