use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    AuthorityEvidenceKindV2, AuthorityEvidenceVerifierV2, AuthorityOperationOutcomeV2,
    AuthorityProvenanceV2, AuthorityProvenanceVerifierV2, AuthorityRoleV2, AuthorityTicketHandleV2,
    DekScopeV2, KeyDescriptorV2, KeyHandleV2, KeyLifecycleV2, OperationRequestIdV2, Result,
    SecureStoreError, StateNamespaceV2, StateRootV2, VerifiedAuthorityEvidenceV2,
    intent_commitment,
};

/// Maximum bytes accepted when recovering one production key operation DTO.
pub const MAX_PRODUCTION_KEY_OPERATION_JSON_BYTES_V2: usize = 512 * 1024;

/// Idempotent request to create exactly one random per-object DEK.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ProductionKeyCreateRequestV2 {
    request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    scope: DekScopeV2,
}

impl ProductionKeyCreateRequestV2 {
    /// Creates a request whose namespace exactly matches the DEK security context.
    pub fn new(
        request_id: OperationRequestIdV2,
        namespace: StateNamespaceV2,
        scope: DekScopeV2,
    ) -> Result<Self> {
        require_scope_namespace(&scope, &namespace)?;
        Ok(Self {
            request_id,
            namespace,
            scope,
        })
    }

    /// Recovers a bounded persisted create intent and re-runs every invariant.
    pub fn from_json_bounded(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PRODUCTION_KEY_OPERATION_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "production key create request exceeds decode byte limit".to_owned(),
            ));
        }
        let wire: ProductionKeyCreateRequestWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        Self::new(wire.request_id, wire.namespace, wire.scope)
    }

    /// Returns the idempotency key.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        &self.request_id
    }

    /// Returns the exact anti-replay namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the exact per-object key scope.
    #[must_use]
    pub fn scope(&self) -> &DekScopeV2 {
        &self.scope
    }

    /// Returns the canonical idempotency-intent commitment.
    pub fn intent_commitment(&self) -> Result<StateRootV2> {
        intent_commitment("production-key-create-request-v2", self)
    }

    /// Validates a successful authority response against this exact request.
    pub fn validate_response(&self, descriptor: &KeyDescriptorV2) -> Result<()> {
        descriptor.validate()?;
        if descriptor.scope() != &self.scope || descriptor.lifecycle() != KeyLifecycleV2::Active {
            return Err(SecureStoreError::Integrity(
                "created key does not match the requested active scope".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionKeyCreateRequestWireV2 {
    request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    scope: DekScopeV2,
}

impl fmt::Debug for ProductionKeyCreateRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionKeyCreateRequestV2")
            .field("request_id", &"[OPAQUE]")
            .field("namespace", &self.namespace)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Strongly consistent descriptor read request with a monotonic generation floor.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ProductionKeyDescribeRequestV2 {
    request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    key_handle: KeyHandleV2,
    expected_scope: DekScopeV2,
    minimum_generation: u64,
}

impl ProductionKeyDescribeRequestV2 {
    /// Creates an exact descriptor read request.
    pub fn new(
        request_id: OperationRequestIdV2,
        namespace: StateNamespaceV2,
        key_handle: KeyHandleV2,
        expected_scope: DekScopeV2,
        minimum_generation: u64,
    ) -> Result<Self> {
        require_scope_namespace(&expected_scope, &namespace)?;
        if minimum_generation == 0 {
            return Err(SecureStoreError::InvalidInput(
                "minimum key generation must be non-zero".to_owned(),
            ));
        }
        Ok(Self {
            request_id,
            namespace,
            key_handle,
            expected_scope,
            minimum_generation,
        })
    }

    /// Returns the operation request identity.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        &self.request_id
    }

    /// Returns the exact anti-replay namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the opaque key handle.
    #[must_use]
    pub fn key_handle(&self) -> &KeyHandleV2 {
        &self.key_handle
    }

    /// Returns the expected immutable key scope.
    #[must_use]
    pub fn expected_scope(&self) -> &DekScopeV2 {
        &self.expected_scope
    }

    /// Returns the caller's last observed generation.
    #[must_use]
    pub const fn minimum_generation(&self) -> u64 {
        self.minimum_generation
    }

    /// Returns the canonical strongly-consistent read intent commitment.
    pub fn intent_commitment(&self) -> Result<StateRootV2> {
        intent_commitment("production-key-describe-request-v2", self)
    }

    /// Rejects stale, relocated, or substituted descriptor responses.
    pub fn validate_response(&self, descriptor: &KeyDescriptorV2) -> Result<()> {
        descriptor.validate()?;
        if descriptor.key_handle() != &self.key_handle || descriptor.scope() != &self.expected_scope
        {
            return Err(SecureStoreError::Integrity(
                "described key identity or scope changed".to_owned(),
            ));
        }
        if descriptor.generation() < self.minimum_generation {
            return Err(SecureStoreError::StateConflict(
                "strongly consistent describe returned a stale generation".to_owned(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ProductionKeyDescribeRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionKeyDescribeRequestV2")
            .field("request_id", &"[OPAQUE]")
            .field("namespace", &self.namespace)
            .field("key_handle", &"[OPAQUE]")
            .field("expected_scope", &self.expected_scope)
            .field("minimum_generation", &self.minimum_generation)
            .finish()
    }
}

/// Idempotent request to begin irreversible destruction at an exact generation.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ProductionKeyDestroyRequestV2 {
    request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    expected_descriptor: KeyDescriptorV2,
}

impl ProductionKeyDestroyRequestV2 {
    /// Creates a destruction request from an exact active descriptor.
    pub fn new(
        request_id: OperationRequestIdV2,
        namespace: StateNamespaceV2,
        expected_descriptor: KeyDescriptorV2,
    ) -> Result<Self> {
        expected_descriptor.validate()?;
        require_scope_namespace(expected_descriptor.scope(), &namespace)?;
        if expected_descriptor.lifecycle() != KeyLifecycleV2::Active {
            return Err(SecureStoreError::StateConflict(
                "new destruction request requires an active descriptor".to_owned(),
            ));
        }
        Ok(Self {
            request_id,
            namespace,
            expected_descriptor,
        })
    }

    /// Recovers a bounded persisted destruction intent.
    pub fn from_json_bounded(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PRODUCTION_KEY_OPERATION_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "production key destroy request exceeds decode byte limit".to_owned(),
            ));
        }
        let wire: ProductionKeyDestroyRequestWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        Self::new(wire.request_id, wire.namespace, wire.expected_descriptor)
    }

    /// Returns the idempotency request identity.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        &self.request_id
    }

    /// Returns the exact anti-replay namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the exact descriptor and generation expected by the caller.
    #[must_use]
    pub fn expected_descriptor(&self) -> &KeyDescriptorV2 {
        &self.expected_descriptor
    }

    /// Returns the canonical idempotency-intent commitment.
    pub fn intent_commitment(&self) -> Result<StateRootV2> {
        intent_commitment("production-key-destroy-request-v2", self)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionKeyDestroyRequestWireV2 {
    request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    expected_descriptor: KeyDescriptorV2,
}

impl fmt::Debug for ProductionKeyDestroyRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionKeyDestroyRequestV2")
            .field("request_id", &"[OPAQUE]")
            .field("namespace", &self.namespace)
            .field("expected_descriptor", &self.expected_descriptor)
            .finish()
    }
}

/// Opaque authority ticket returned after a destruction request is durably accepted.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct KeyDestroyTicketV2 {
    ticket_handle: AuthorityTicketHandleV2,
    request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    provenance: AuthorityProvenanceV2,
    pending_descriptor: KeyDescriptorV2,
    request_intent_commitment: StateRootV2,
}

impl KeyDestroyTicketV2 {
    /// Validates an authority-returned opaque ticket against the initiating request.
    pub fn authority_accepted(
        ticket_handle: AuthorityTicketHandleV2,
        request: &ProductionKeyDestroyRequestV2,
        provenance: AuthorityProvenanceV2,
        pending_descriptor: KeyDescriptorV2,
    ) -> Result<Self> {
        require_role(&provenance, AuthorityRoleV2::KeyAuthority)?;
        pending_descriptor.validate()?;
        let expected_pending = request.expected_descriptor.authority_destroy_pending()?;
        if pending_descriptor != expected_pending {
            return Err(SecureStoreError::Integrity(
                "destroy ticket does not bind the exact pending descriptor".to_owned(),
            ));
        }
        Ok(Self {
            ticket_handle,
            request_id: request.request_id.clone(),
            namespace: request.namespace.clone(),
            provenance,
            pending_descriptor,
            request_intent_commitment: request.intent_commitment()?,
        })
    }

    /// Recovers a bounded persisted ticket against configured provenance.
    pub fn from_json_bounded(
        bytes: &[u8],
        expected_provenance: &AuthorityProvenanceV2,
    ) -> Result<Self> {
        if bytes.len() > MAX_PRODUCTION_KEY_OPERATION_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "key destroy ticket exceeds decode byte limit".to_owned(),
            ));
        }
        let wire: KeyDestroyTicketWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        let expected_wire = serde_json::to_value(expected_provenance)
            .map_err(|_| SecureStoreError::Serialization)?;
        if wire.provenance != expected_wire {
            return Err(SecureStoreError::Integrity(
                "persisted key destroy ticket provenance changed".to_owned(),
            ));
        }
        wire.pending_descriptor.validate()?;
        let active = KeyDescriptorV2::authority_active(
            wire.pending_descriptor.key_handle().clone(),
            wire.pending_descriptor.scope().clone(),
        )?;
        let request = ProductionKeyDestroyRequestV2::new(wire.request_id, wire.namespace, active)?;
        let ticket = Self::authority_accepted(
            wire.ticket_handle,
            &request,
            expected_provenance.clone(),
            wire.pending_descriptor,
        )?;
        if ticket.request_intent_commitment != wire.request_intent_commitment {
            return Err(SecureStoreError::Integrity(
                "persisted key destroy ticket intent changed".to_owned(),
            ));
        }
        Ok(ticket)
    }

    /// Returns the opaque provider ticket handle.
    #[must_use]
    pub fn ticket_handle(&self) -> &AuthorityTicketHandleV2 {
        &self.ticket_handle
    }

    /// Returns the original destruction request identity.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        &self.request_id
    }

    /// Returns the exact anti-replay namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the authority provenance that accepted the ticket.
    #[must_use]
    pub fn provenance(&self) -> &AuthorityProvenanceV2 {
        &self.provenance
    }

    /// Returns the exact destroy-pending descriptor.
    #[must_use]
    pub fn pending_descriptor(&self) -> &KeyDescriptorV2 {
        &self.pending_descriptor
    }

    /// Returns the initiating request commitment.
    #[must_use]
    pub fn request_intent_commitment(&self) -> &StateRootV2 {
        &self.request_intent_commitment
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyDestroyTicketWireV2 {
    ticket_handle: AuthorityTicketHandleV2,
    request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    provenance: serde_json::Value,
    pending_descriptor: KeyDescriptorV2,
    request_intent_commitment: StateRootV2,
}

impl fmt::Debug for KeyDestroyTicketV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyDestroyTicketV2")
            .field("ticket_handle", &"[OPAQUE]")
            .field("request_id", &"[OPAQUE]")
            .field("namespace", &self.namespace)
            .field("provenance", &self.provenance)
            .field("pending_descriptor", &self.pending_descriptor)
            .field("request_intent_commitment", &"[COMMITMENT]")
            .finish()
    }
}

/// Idempotent poll request for one opaque destruction ticket.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ProductionKeyDestroyPollRequestV2 {
    request_id: OperationRequestIdV2,
    ticket: KeyDestroyTicketV2,
}

impl ProductionKeyDestroyPollRequestV2 {
    /// Creates a bounded poll request.
    #[must_use]
    pub const fn new(request_id: OperationRequestIdV2, ticket: KeyDestroyTicketV2) -> Self {
        Self { request_id, ticket }
    }

    /// Returns this poll's idempotency identity.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        &self.request_id
    }

    /// Returns the authority-issued destruction ticket.
    #[must_use]
    pub fn ticket(&self) -> &KeyDestroyTicketV2 {
        &self.ticket
    }

    /// Returns the canonical poll intent commitment.
    pub fn intent_commitment(&self) -> Result<StateRootV2> {
        intent_commitment("production-key-destroy-poll-v2", self)
    }
}

impl fmt::Debug for ProductionKeyDestroyPollRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionKeyDestroyPollRequestV2")
            .field("request_id", &"[OPAQUE]")
            .field("ticket", &self.ticket)
            .finish()
    }
}

/// Signed, authority-created proof that one exact DEK was destroyed.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct KeyDestructionEvidenceV2 {
    ticket: KeyDestroyTicketV2,
    destroyed_descriptor: KeyDescriptorV2,
    authority_evidence: VerifiedAuthorityEvidenceV2,
}

impl KeyDestructionEvidenceV2 {
    /// Binds already verified authority evidence to an exact destroyed descriptor.
    pub fn from_verified(
        ticket: KeyDestroyTicketV2,
        destroyed_descriptor: KeyDescriptorV2,
        authority_evidence: VerifiedAuthorityEvidenceV2,
    ) -> Result<Self> {
        destroyed_descriptor.validate()?;
        let expected = ticket
            .pending_descriptor
            .authority_destroyed(authority_evidence.evidence_handle().clone())?;
        if destroyed_descriptor != expected {
            return Err(SecureStoreError::Integrity(
                "destruction evidence descriptor is stale or substituted".to_owned(),
            ));
        }
        let subject = key_destruction_subject(&ticket, &destroyed_descriptor)?;
        if authority_evidence.kind() != AuthorityEvidenceKindV2::KeyDestroyed
            || authority_evidence.provenance() != &ticket.provenance
            || authority_evidence.namespace() != &ticket.namespace
            || authority_evidence.request_id() != &ticket.request_id
            || authority_evidence.subject_commitment() != &subject
        {
            return Err(SecureStoreError::Integrity(
                "authority evidence does not bind the exact destroyed key ticket".to_owned(),
            ));
        }
        Ok(Self {
            ticket,
            destroyed_descriptor,
            authority_evidence,
        })
    }

    /// Returns the original authority ticket.
    #[must_use]
    pub fn ticket(&self) -> &KeyDestroyTicketV2 {
        &self.ticket
    }

    /// Returns the exact final key descriptor.
    #[must_use]
    pub fn destroyed_descriptor(&self) -> &KeyDescriptorV2 {
        &self.destroyed_descriptor
    }

    /// Returns the signed evidence envelope.
    #[must_use]
    pub fn authority_evidence(&self) -> &VerifiedAuthorityEvidenceV2 {
        &self.authority_evidence
    }

    /// Rechecks signature and current authority trust/revocation state.
    pub fn verify_current(
        &self,
        evaluated_at_micros: u64,
        verifier: &dyn AuthorityEvidenceVerifierV2,
    ) -> Result<()> {
        self.authority_evidence.verify_exact(
            AuthorityEvidenceKindV2::KeyDestroyed,
            self.ticket.provenance(),
            self.ticket.namespace(),
            self.ticket.request_id(),
            &key_destruction_subject(&self.ticket, &self.destroyed_descriptor)?,
            evaluated_at_micros,
            verifier,
        )
    }
}

impl fmt::Debug for KeyDestructionEvidenceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyDestructionEvidenceV2")
            .field("ticket", &self.ticket)
            .field("destroyed_descriptor", &self.destroyed_descriptor)
            .field("authority_evidence", &self.authority_evidence)
            .finish()
    }
}

/// Strongly validated state returned by destruction polling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum KeyDestroyPollV2 {
    /// Destruction remains pending and content access stays denied.
    Pending {
        /// Exact authority ticket.
        ticket: Box<KeyDestroyTicketV2>,
        /// Current destroy-pending descriptor.
        descriptor: Box<KeyDescriptorV2>,
    },
    /// The authority returned signed evidence of irreversible destruction.
    Destroyed(Box<KeyDestructionEvidenceV2>),
}

impl KeyDestroyPollV2 {
    /// Creates a pending poll response bound to the ticket's exact descriptor.
    pub fn pending(ticket: KeyDestroyTicketV2, descriptor: KeyDescriptorV2) -> Result<Self> {
        if descriptor != ticket.pending_descriptor {
            return Err(SecureStoreError::Integrity(
                "pending poll descriptor does not match the authority ticket".to_owned(),
            ));
        }
        Ok(Self::Pending {
            ticket: Box::new(ticket),
            descriptor: Box::new(descriptor),
        })
    }
}

/// Transport/backend contract for a production-grade asynchronous key authority.
///
/// Implementations MUST be linearizable for `create_or_get`, strongly
/// consistent for `describe_strongly_consistent`, bind each request ID to one
/// canonical intent forever, and return `Unavailable` rather than stale cache
/// data when the authority cannot answer. Key bytes never cross this interface.
/// Direct calls are non-authoritative for integration because they do not
/// enforce a fresh host trust decision; production callers use
/// [`CurrentProductionKeyAuthorityV2`].
pub trait ProductionKeyAuthorityV2: Send + Sync {
    /// Returns authenticated provenance for this concrete adapter deployment.
    fn provenance(&self) -> &AuthorityProvenanceV2;

    /// Creates one random DEK, or returns the exact previous result for a retry.
    fn create_or_get(
        &self,
        request: &ProductionKeyCreateRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDescriptorV2>>;

    /// Performs a linearizable, cache-bypassing descriptor read.
    fn describe_strongly_consistent(
        &self,
        request: &ProductionKeyDescribeRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDescriptorV2>>;

    /// Durably accepts destruction and returns an opaque polling ticket.
    fn request_destroy(
        &self,
        request: &ProductionKeyDestroyRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDestroyTicketV2>>;

    /// Returns pending or authority-created signed destruction evidence.
    fn poll_destroy(
        &self,
        request: &ProductionKeyDestroyPollRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDestroyPollV2>>;
}

/// Integration-eligible key-authority view that rechecks host trust on every use.
pub struct CurrentProductionKeyAuthorityV2<'a> {
    backend: &'a dyn ProductionKeyAuthorityV2,
    provenance_verifier: &'a dyn AuthorityProvenanceVerifierV2,
    evidence_verifier: &'a dyn AuthorityEvidenceVerifierV2,
}

impl<'a> CurrentProductionKeyAuthorityV2<'a> {
    /// Binds the backend only after a current production provenance decision.
    pub fn bind(
        backend: &'a dyn ProductionKeyAuthorityV2,
        evaluated_at_micros: u64,
        provenance_verifier: &'a dyn AuthorityProvenanceVerifierV2,
        evidence_verifier: &'a dyn AuthorityEvidenceVerifierV2,
    ) -> Result<Self> {
        require_role(backend.provenance(), AuthorityRoleV2::KeyAuthority)?;
        backend
            .provenance()
            .require_current(evaluated_at_micros, provenance_verifier)?;
        Ok(Self {
            backend,
            provenance_verifier,
            evidence_verifier,
        })
    }

    /// Performs a freshness-checked idempotent create-or-get.
    pub fn create_or_get(
        &self,
        evaluated_at_micros: u64,
        request: &ProductionKeyCreateRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDescriptorV2>> {
        self.require_current(evaluated_at_micros)?;
        let outcome = self.backend.create_or_get(request)?;
        match &outcome {
            AuthorityOperationOutcomeV2::Applied(value)
            | AuthorityOperationOutcomeV2::AlreadyApplied(value) => {
                request.validate_response(value)?;
            }
            AuthorityOperationOutcomeV2::Conflict { .. }
            | AuthorityOperationOutcomeV2::Unavailable => {}
        }
        Ok(outcome)
    }

    /// Performs a freshness-checked strongly consistent descriptor read.
    pub fn describe_strongly_consistent(
        &self,
        evaluated_at_micros: u64,
        request: &ProductionKeyDescribeRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDescriptorV2>> {
        self.require_current(evaluated_at_micros)?;
        let outcome = self.backend.describe_strongly_consistent(request)?;
        match &outcome {
            AuthorityOperationOutcomeV2::Applied(value)
            | AuthorityOperationOutcomeV2::AlreadyApplied(value) => {
                request.validate_response(value)?;
            }
            AuthorityOperationOutcomeV2::Conflict { .. }
            | AuthorityOperationOutcomeV2::Unavailable => {}
        }
        Ok(outcome)
    }

    /// Performs a freshness-checked destruction request and validates its ticket.
    pub fn request_destroy(
        &self,
        evaluated_at_micros: u64,
        request: &ProductionKeyDestroyRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDestroyTicketV2>> {
        self.require_current(evaluated_at_micros)?;
        let outcome = self.backend.request_destroy(request)?;
        match &outcome {
            AuthorityOperationOutcomeV2::Applied(ticket)
            | AuthorityOperationOutcomeV2::AlreadyApplied(ticket) => {
                validate_destroy_ticket(ticket, request, self.backend.provenance())?;
            }
            AuthorityOperationOutcomeV2::Conflict { .. }
            | AuthorityOperationOutcomeV2::Unavailable => {}
        }
        Ok(outcome)
    }

    /// Performs a freshness-checked poll and re-verifies terminal evidence.
    pub fn poll_destroy(
        &self,
        evaluated_at_micros: u64,
        request: &ProductionKeyDestroyPollRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDestroyPollV2>> {
        self.require_current(evaluated_at_micros)?;
        let outcome = self.backend.poll_destroy(request)?;
        match &outcome {
            AuthorityOperationOutcomeV2::Applied(value)
            | AuthorityOperationOutcomeV2::AlreadyApplied(value) => match value {
                KeyDestroyPollV2::Pending { ticket, descriptor } => {
                    if ticket.as_ref() != request.ticket()
                        || descriptor.as_ref() != request.ticket().pending_descriptor()
                    {
                        return Err(SecureStoreError::Integrity(
                            "key poll returned a substituted pending ticket".to_owned(),
                        ));
                    }
                }
                KeyDestroyPollV2::Destroyed(evidence) => {
                    if evidence.ticket() != request.ticket() {
                        return Err(SecureStoreError::Integrity(
                            "key poll returned destruction evidence for another ticket".to_owned(),
                        ));
                    }
                    evidence.verify_current(evaluated_at_micros, self.evidence_verifier)?;
                }
            },
            AuthorityOperationOutcomeV2::Conflict { .. }
            | AuthorityOperationOutcomeV2::Unavailable => {}
        }
        Ok(outcome)
    }

    fn require_current(&self, evaluated_at_micros: u64) -> Result<()> {
        self.backend
            .provenance()
            .require_current(evaluated_at_micros, self.provenance_verifier)
    }
}

impl fmt::Debug for CurrentProductionKeyAuthorityV2<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentProductionKeyAuthorityV2")
            .field("provenance", self.backend.provenance())
            .finish_non_exhaustive()
    }
}

fn validate_destroy_ticket(
    ticket: &KeyDestroyTicketV2,
    request: &ProductionKeyDestroyRequestV2,
    provenance: &AuthorityProvenanceV2,
) -> Result<()> {
    if ticket.request_id() != request.request_id()
        || ticket.namespace() != request.namespace()
        || ticket.provenance() != provenance
        || ticket.request_intent_commitment() != &request.intent_commitment()?
        || ticket.pending_descriptor()
            != &request.expected_descriptor().authority_destroy_pending()?
    {
        return Err(SecureStoreError::Integrity(
            "key authority returned a ticket for another request".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn key_destruction_subject(
    ticket: &KeyDestroyTicketV2,
    destroyed_descriptor: &KeyDescriptorV2,
) -> Result<StateRootV2> {
    #[derive(Serialize)]
    struct Subject<'a> {
        ticket: &'a KeyDestroyTicketV2,
        destroyed_descriptor: &'a KeyDescriptorV2,
    }
    intent_commitment(
        "key-destruction-evidence-subject-v2",
        &Subject {
            ticket,
            destroyed_descriptor,
        },
    )
}

fn require_scope_namespace(scope: &DekScopeV2, namespace: &StateNamespaceV2) -> Result<()> {
    let context = scope.security_context();
    if context.database_id() != namespace.database_id()
        || context.workspace_id() != namespace.workspace_id()
    {
        return Err(SecureStoreError::Integrity(
            "DEK scope database/workspace does not match operation namespace".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn require_role(
    provenance: &AuthorityProvenanceV2,
    role: AuthorityRoleV2,
) -> Result<()> {
    if provenance.role() != role {
        return Err(SecureStoreError::Integrity(
            "authority provenance role does not match adapter contract".to_owned(),
        ));
    }
    Ok(())
}
