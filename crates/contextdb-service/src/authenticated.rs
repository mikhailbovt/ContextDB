use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{ErrorCode, RequestContext, ServiceError, ServiceResult};

/// Explicit operation capabilities resolved by the host authorization layer.
///
/// These grants are intentionally distinct from semantic scopes: a caller may
/// be allowed to read one project scope without being allowed to delete,
/// administer, subscribe, or submit raw evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Capture one legacy observation.
    Observe,
    /// Ingest a resumable source snapshot.
    StreamIngest,
    /// Recall policy-authorized memory.
    Recall,
    /// Correct an existing memory with a successor record.
    Correct,
    /// Retract a memory while retaining its evidence and history.
    Forget,
    /// Irreversibly erase content through the hard-delete path.
    HardDelete,
    /// Materialize ordinary memory records.
    ReadMemory,
    /// Traverse authorized graph structure.
    Traverse,
    /// Materialize raw evidence.
    ReadEvidence,
    /// Materialize conflict state.
    ReadConflict,
    /// Subscribe to memory change notifications.
    Subscribe,
    /// Execute agent-runtime lifecycle operations.
    Runtime,
    /// Execute maintenance operations.
    Maintenance,
    /// Execute administrative operations.
    Admin,
    /// Permit raw evidence to cross the service boundary.
    RawEvidence,
    /// Permit policy-authorized model processing.
    ModelProcessing,
}

/// Evidence that authentication was completed before application content was
/// inspected. A deployment remains responsible for establishing the channel
/// identity or verifying the signature against its trust store.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthenticationEvidence {
    /// Identity established by an authenticated transport channel.
    AuthenticatedChannel {
        /// Deployment-local channel identity.
        channel_id: String,
        /// Authenticated peer principal.
        peer_identity: String,
        /// Lowercase BLAKE3 digest binding transport metadata to the request.
        binding_digest: String,
    },
    /// Detached request signature verified by the transport boundary.
    RequestSignature {
        /// Signature algorithm. Version 1 admits `ed25519` only.
        algorithm: String,
        /// Deployment trust-store key identifier.
        key_id: String,
        /// Lowercase hexadecimal Ed25519 signature.
        signature: String,
        /// BLAKE3 digest of the unsigned authenticated request context.
        signed_context_digest: String,
    },
}

/// Fully attributed request context required by all new v1 domain, streaming,
/// subscription, runtime, maintenance, and administrative methods.
///
/// The nested [`RequestContext`] is retained as a compatibility layer for the
/// already-published embedded Observe/Recall surface. This wrapper adds the
/// caller/agent/subject distinction and authentication evidence without a
/// breaking Rust struct-field change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedRequestContext {
    /// Resolved semantic authorization context.
    pub request: RequestContext,
    /// Human, service, or organization accountable for the request.
    pub actor_id: String,
    /// Software agent executing on behalf of the actor.
    pub agent_id: String,
    /// Optional active runtime session.
    pub session_id: Option<String>,
    /// Explicit operation grants resolved by host policy.
    pub capability_grants: BTreeSet<Capability>,
    /// Authentication evidence established before content processing.
    pub authentication: AuthenticationEvidence,
}

impl AuthenticatedRequestContext {
    /// Returns the deterministic digest signed by request-signature evidence.
    pub fn unsigned_context_digest(&self) -> ServiceResult<String> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            schema_version: u16,
            request: &'a RequestContext,
            actor_id: &'a str,
            agent_id: &'a str,
            session_id: &'a Option<String>,
            capability_grants: &'a BTreeSet<Capability>,
        }

        let bytes = serde_json::to_vec(&Unsigned {
            schema_version: crate::SERVICE_SCHEMA_VERSION,
            request: &self.request,
            actor_id: &self.actor_id,
            agent_id: &self.agent_id,
            session_id: &self.session_id,
            capability_grants: &self.capability_grants,
        })
        .map_err(|_| {
            ServiceError::new(
                ErrorCode::IntegrityFailure,
                "authenticated context serialization failed",
                false,
            )
        })?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }

    /// Returns the stable authorization identity used to bind resumable
    /// cursors. Transient request IDs and transport evidence are intentionally
    /// excluded so a reconnect can present fresh anti-replay evidence without
    /// changing subject, scope, purpose, actor, agent, or session authority.
    pub fn authorization_binding_digest(&self) -> ServiceResult<String> {
        #[derive(Serialize)]
        struct Binding<'a> {
            schema_version: u16,
            workspace_id: &'a str,
            subject_id: &'a str,
            audiences: &'a BTreeSet<String>,
            scopes: &'a BTreeSet<String>,
            purpose: &'a str,
            clearance: crate::Sensitivity,
            actor_id: &'a str,
            agent_id: &'a str,
            session_id: &'a Option<String>,
        }

        let bytes = serde_json::to_vec(&Binding {
            schema_version: crate::SERVICE_SCHEMA_VERSION,
            workspace_id: &self.request.workspace_id,
            subject_id: &self.request.subject_id,
            audiences: &self.request.audiences,
            scopes: &self.request.scopes,
            purpose: &self.request.purpose,
            clearance: self.request.clearance,
            actor_id: &self.actor_id,
            agent_id: &self.agent_id,
            session_id: &self.session_id,
        })
        .map_err(|_| {
            ServiceError::new(
                ErrorCode::IntegrityFailure,
                "authorization binding serialization failed",
                false,
            )
        })?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }

    /// Validates caller/agent/session attribution and authentication evidence
    /// without inspecting any operation payload.
    ///
    /// Transports call this immediately after decoding the context envelope and
    /// before operation payload validation or materialization. Capability-
    /// specific checks remain in the service method.
    pub fn validate_authentication(&self) -> ServiceResult<()> {
        validate_legacy_context(&self.request)?;
        validate_identifier(&self.actor_id)?;
        validate_identifier(&self.agent_id)?;
        if let Some(session_id) = &self.session_id {
            validate_identifier(session_id)?;
        }
        if self.capability_grants.len() > 256 {
            return Err(ServiceError::new(
                ErrorCode::ResourceExhausted,
                "capability grant set exceeds the service limit",
                false,
            ));
        }
        validate_authentication(self)
    }
}

pub(crate) fn validate_legacy_context(context: &RequestContext) -> ServiceResult<()> {
    validate_identifier(&context.request_id)?;
    validate_identifier(&context.workspace_id)?;
    validate_identifier(&context.subject_id)?;
    validate_identifier(&context.purpose)?;
    validate_strings(&context.audiences)?;
    validate_strings(&context.scopes)
}

pub(crate) fn require_capability(
    context: &AuthenticatedRequestContext,
    required: Capability,
) -> ServiceResult<()> {
    context.validate_authentication()?;
    if !context.capability_grants.contains(&required) {
        return Err(ServiceError::new(
            ErrorCode::Unauthorized,
            "required capability is absent",
            false,
        )
        .with_context(
            Vec::new(),
            Some(format!("capability:{}", capability_name(required))),
            Some("request an explicit capability grant".to_owned()),
            None,
        ));
    }
    Ok(())
}

/// Validates the complete authenticated context and requires one explicit
/// operation capability without inspecting operation content.
///
/// Transport adapters use this after authenticating their trusted gateway and
/// before decoding content for methods that are known to be unsupported by the
/// selected profile.
pub fn authorize_capability(
    context: &AuthenticatedRequestContext,
    required: Capability,
) -> ServiceResult<()> {
    require_capability(context, required)
}

fn validate_authentication(context: &AuthenticatedRequestContext) -> ServiceResult<()> {
    match &context.authentication {
        AuthenticationEvidence::AuthenticatedChannel {
            channel_id,
            peer_identity,
            binding_digest,
        } => {
            validate_identifier(channel_id)?;
            validate_identifier(peer_identity)?;
            validate_hex(binding_digest, 64)?;
            if peer_identity != &context.actor_id {
                return Err(ServiceError::new(
                    ErrorCode::Unauthorized,
                    "authenticated channel principal does not match actor",
                    false,
                ));
            }
        }
        AuthenticationEvidence::RequestSignature {
            algorithm,
            key_id,
            signature,
            signed_context_digest,
        } => {
            if algorithm != "ed25519" {
                return Err(ServiceError::new(
                    ErrorCode::FormatIncompatible,
                    "v1 request signatures require ed25519",
                    false,
                ));
            }
            validate_identifier(key_id)?;
            validate_hex(signature, 128)?;
            validate_hex(signed_context_digest, 64)?;
            if *signed_context_digest != context.unsigned_context_digest()? {
                return Err(ServiceError::new(
                    ErrorCode::Unauthorized,
                    "request signature is bound to another context",
                    false,
                ));
            }
        }
    }
    Ok(())
}

fn validate_strings(values: &BTreeSet<String>) -> ServiceResult<()> {
    if values.len() > 4_096 {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "request set exceeds the service limit",
            false,
        ));
    }
    for value in values {
        validate_identifier(value)?;
    }
    Ok(())
}

fn validate_identifier(value: &str) -> ServiceResult<()> {
    if value.trim().is_empty() || value.len() > 1_024 || value.contains('\0') {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "authentication metadata contains an invalid bounded string",
            false,
        ));
    }
    Ok(())
}

fn validate_hex(value: &str, length: usize) -> ServiceResult<()> {
    if value.len() != length
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "authentication digest or signature is not canonical lowercase hexadecimal",
            false,
        ));
    }
    Ok(())
}

const fn capability_name(value: Capability) -> &'static str {
    match value {
        Capability::Observe => "observe",
        Capability::StreamIngest => "stream_ingest",
        Capability::Recall => "recall",
        Capability::Correct => "correct",
        Capability::Forget => "forget",
        Capability::HardDelete => "hard_delete",
        Capability::ReadMemory => "read_memory",
        Capability::Traverse => "traverse",
        Capability::ReadEvidence => "read_evidence",
        Capability::ReadConflict => "read_conflict",
        Capability::Subscribe => "subscribe",
        Capability::Runtime => "runtime",
        Capability::Maintenance => "maintenance",
        Capability::Admin => "admin",
        Capability::RawEvidence => "raw_evidence",
        Capability::ModelProcessing => "model_processing",
    }
}
