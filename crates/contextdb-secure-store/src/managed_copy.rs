use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    AuthorityEvidenceKindV2, AuthorityEvidenceVerifierV2, AuthorityOperationOutcomeV2,
    AuthorityProvenanceV2, AuthorityProvenanceVerifierV2, AuthorityRoleV2, AuthorityTicketHandleV2,
    DeletionClosureClassV2, DeletionHandleV2, DeletionTargetHandleV2, ManagedCopyDispositionV2,
    OperationRequestIdV2, Result, SecureStoreError, StateNamespaceV2, StateRootV2,
    VerifiedAuthorityEvidenceV2, intent_commitment, require_role,
};

/// Maximum bytes accepted when recovering one managed-copy deletion intent.
pub const MAX_MANAGED_COPY_DELETE_REQUEST_JSON_BYTES_V2: usize = 128 * 1024;
/// Maximum bytes accepted when recovering one managed-copy authority ticket.
pub const MAX_MANAGED_COPY_DELETE_TICKET_JSON_BYTES_V2: usize = 256 * 1024;

/// Idempotent deletion request for one provider/export/backup copy.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ManagedCopyDeleteRequestV2 {
    request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    deletion: DeletionHandleV2,
    target: DeletionTargetHandleV2,
    class: DeletionClosureClassV2,
    copy_generation: u64,
    inventory_commitment: StateRootV2,
}

impl ManagedCopyDeleteRequestV2 {
    /// Creates an exact managed-copy deletion intent.
    #[allow(
        clippy::too_many_arguments,
        reason = "managed-copy intent binds every authoritative inventory dimension"
    )]
    pub fn new(
        request_id: OperationRequestIdV2,
        namespace: StateNamespaceV2,
        deletion: DeletionHandleV2,
        target: DeletionTargetHandleV2,
        class: DeletionClosureClassV2,
        copy_generation: u64,
        inventory_commitment: StateRootV2,
    ) -> Result<Self> {
        if !class.is_managed_copy() || copy_generation == 0 {
            return Err(SecureStoreError::InvalidInput(
                "managed-copy request class or generation is invalid".to_owned(),
            ));
        }
        Ok(Self {
            request_id,
            namespace,
            deletion,
            target,
            class,
            copy_generation,
            inventory_commitment,
        })
    }

    /// Recovers a bounded persisted intent and re-runs every invariant.
    pub fn from_json_bounded(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MANAGED_COPY_DELETE_REQUEST_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "managed-copy request exceeds decode byte limit".to_owned(),
            ));
        }
        let wire: ManagedCopyDeleteRequestWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        Self::try_from(wire)
    }

    /// Returns the idempotency request identity.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        &self.request_id
    }

    /// Returns the exact destination namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the owning hard-delete workflow.
    #[must_use]
    pub fn deletion(&self) -> &DeletionHandleV2 {
        &self.deletion
    }

    /// Returns the opaque managed-copy target.
    #[must_use]
    pub fn target(&self) -> &DeletionTargetHandleV2 {
        &self.target
    }

    /// Returns the provider/export/backup closure class.
    #[must_use]
    pub const fn class(&self) -> DeletionClosureClassV2 {
        self.class
    }

    /// Returns the exact provider-side copy generation.
    #[must_use]
    pub const fn copy_generation(&self) -> u64 {
        self.copy_generation
    }

    /// Returns the authoritative inventory commitment that identified the copy.
    #[must_use]
    pub fn inventory_commitment(&self) -> &StateRootV2 {
        &self.inventory_commitment
    }

    /// Returns the canonical idempotency-intent commitment.
    pub fn intent_commitment(&self) -> Result<StateRootV2> {
        intent_commitment("managed-copy-delete-request-v2", self)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedCopyDeleteRequestWireV2 {
    request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    deletion: DeletionHandleV2,
    target: DeletionTargetHandleV2,
    class: DeletionClosureClassV2,
    copy_generation: u64,
    inventory_commitment: StateRootV2,
}

impl TryFrom<ManagedCopyDeleteRequestWireV2> for ManagedCopyDeleteRequestV2 {
    type Error = SecureStoreError;

    fn try_from(value: ManagedCopyDeleteRequestWireV2) -> Result<Self> {
        Self::new(
            value.request_id,
            value.namespace,
            value.deletion,
            value.target,
            value.class,
            value.copy_generation,
            value.inventory_commitment,
        )
    }
}

impl fmt::Debug for ManagedCopyDeleteRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedCopyDeleteRequestV2")
            .field("request_id", &"[OPAQUE]")
            .field("namespace", &self.namespace)
            .field("deletion", &"[OPAQUE]")
            .field("target", &"[OPAQUE]")
            .field("class", &self.class)
            .field("copy_generation", &self.copy_generation)
            .field("inventory_commitment", &"[COMMITMENT]")
            .finish()
    }
}

/// Opaque provider ticket durably accepting one exact managed-copy intent.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ManagedCopyDeleteTicketV2 {
    ticket_handle: AuthorityTicketHandleV2,
    provenance: AuthorityProvenanceV2,
    request: ManagedCopyDeleteRequestV2,
    request_intent_commitment: StateRootV2,
}

impl ManagedCopyDeleteTicketV2 {
    /// Validates a ticket returned by the responsible managed-copy authority.
    pub fn authority_accepted(
        ticket_handle: AuthorityTicketHandleV2,
        provenance: AuthorityProvenanceV2,
        request: ManagedCopyDeleteRequestV2,
    ) -> Result<Self> {
        require_role(&provenance, AuthorityRoleV2::ManagedCopyProvider)?;
        let request_intent_commitment = request.intent_commitment()?;
        Ok(Self {
            ticket_handle,
            provenance,
            request,
            request_intent_commitment,
        })
    }

    /// Recovers a bounded persisted ticket against configured authority provenance.
    pub fn from_json_bounded(
        bytes: &[u8],
        expected_provenance: &AuthorityProvenanceV2,
    ) -> Result<Self> {
        if bytes.len() > MAX_MANAGED_COPY_DELETE_TICKET_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "managed-copy ticket exceeds decode byte limit".to_owned(),
            ));
        }
        let wire: ManagedCopyDeleteTicketWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        let expected_wire = serde_json::to_value(expected_provenance)
            .map_err(|_| SecureStoreError::Serialization)?;
        if wire.provenance != expected_wire {
            return Err(SecureStoreError::Integrity(
                "persisted managed-copy ticket provenance changed".to_owned(),
            ));
        }
        let request = ManagedCopyDeleteRequestV2::try_from(wire.request)?;
        let ticket =
            Self::authority_accepted(wire.ticket_handle, expected_provenance.clone(), request)?;
        if ticket.request_intent_commitment != wire.request_intent_commitment {
            return Err(SecureStoreError::Integrity(
                "persisted managed-copy ticket intent was modified".to_owned(),
            ));
        }
        Ok(ticket)
    }

    /// Returns the opaque provider ticket.
    #[must_use]
    pub fn ticket_handle(&self) -> &AuthorityTicketHandleV2 {
        &self.ticket_handle
    }

    /// Returns the provider authority provenance.
    #[must_use]
    pub fn provenance(&self) -> &AuthorityProvenanceV2 {
        &self.provenance
    }

    /// Returns the exact accepted request.
    #[must_use]
    pub fn request(&self) -> &ManagedCopyDeleteRequestV2 {
        &self.request
    }

    /// Returns the accepted request commitment.
    #[must_use]
    pub fn request_intent_commitment(&self) -> &StateRootV2 {
        &self.request_intent_commitment
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedCopyDeleteTicketWireV2 {
    ticket_handle: AuthorityTicketHandleV2,
    provenance: serde_json::Value,
    request: ManagedCopyDeleteRequestWireV2,
    request_intent_commitment: StateRootV2,
}

impl fmt::Debug for ManagedCopyDeleteTicketV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedCopyDeleteTicketV2")
            .field("ticket_handle", &"[OPAQUE]")
            .field("provenance", &self.provenance)
            .field("request", &self.request)
            .field("request_intent_commitment", &"[COMMITMENT]")
            .finish()
    }
}

/// Idempotent poll request for one managed-copy deletion ticket.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ManagedCopyDeletePollRequestV2 {
    request_id: OperationRequestIdV2,
    ticket: ManagedCopyDeleteTicketV2,
}

impl ManagedCopyDeletePollRequestV2 {
    /// Creates a poll request for an authority-issued ticket.
    #[must_use]
    pub const fn new(request_id: OperationRequestIdV2, ticket: ManagedCopyDeleteTicketV2) -> Self {
        Self { request_id, ticket }
    }

    /// Returns this poll's request identity.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        &self.request_id
    }

    /// Returns the provider ticket.
    #[must_use]
    pub fn ticket(&self) -> &ManagedCopyDeleteTicketV2 {
        &self.ticket
    }
}

impl fmt::Debug for ManagedCopyDeletePollRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedCopyDeletePollRequestV2")
            .field("request_id", &"[OPAQUE]")
            .field("ticket", &self.ticket)
            .finish()
    }
}

/// Terminal authority disposition for a managed copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedCopyTerminalDispositionV2 {
    /// The responsible authority verified deletion.
    Deleted,
    /// The responsible authority verified that no copy existed.
    ProvenAbsent,
    /// The copy is beyond verifiable control; terminal for the adapter but
    /// deliberately incomplete for hard-delete workflow completion.
    OutsideControl,
}

impl ManagedCopyTerminalDispositionV2 {
    /// Returns whether no further adapter polling is expected.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        true
    }

    /// Returns whether this disposition can satisfy deletion completeness.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Deleted | Self::ProvenAbsent)
    }

    const fn evidence_kind(self) -> AuthorityEvidenceKindV2 {
        match self {
            Self::Deleted => AuthorityEvidenceKindV2::ManagedCopyDeleted,
            Self::ProvenAbsent => AuthorityEvidenceKindV2::ManagedCopyProvenAbsent,
            Self::OutsideControl => AuthorityEvidenceKindV2::ManagedCopyOutsideControl,
        }
    }
}

/// Signed terminal provider evidence for one exact managed-copy ticket.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ManagedCopyTerminalEvidenceV2 {
    ticket: ManagedCopyDeleteTicketV2,
    disposition: ManagedCopyTerminalDispositionV2,
    authority_evidence: VerifiedAuthorityEvidenceV2,
}

impl ManagedCopyTerminalEvidenceV2 {
    /// Binds verified authority evidence to an exact ticket and terminal outcome.
    pub fn from_verified(
        ticket: ManagedCopyDeleteTicketV2,
        disposition: ManagedCopyTerminalDispositionV2,
        authority_evidence: VerifiedAuthorityEvidenceV2,
    ) -> Result<Self> {
        let subject = managed_copy_terminal_subject(&ticket, disposition)?;
        if authority_evidence.kind() != disposition.evidence_kind()
            || authority_evidence.provenance() != ticket.provenance()
            || authority_evidence.namespace() != ticket.request().namespace()
            || authority_evidence.request_id() != ticket.request().request_id()
            || authority_evidence.subject_commitment() != &subject
        {
            return Err(SecureStoreError::Integrity(
                "managed-copy evidence does not bind the exact ticket outcome".to_owned(),
            ));
        }
        Ok(Self {
            ticket,
            disposition,
            authority_evidence,
        })
    }

    /// Returns the original provider ticket.
    #[must_use]
    pub fn ticket(&self) -> &ManagedCopyDeleteTicketV2 {
        &self.ticket
    }

    /// Returns the terminal provider disposition.
    #[must_use]
    pub const fn disposition(&self) -> ManagedCopyTerminalDispositionV2 {
        self.disposition
    }

    /// Returns signed provider evidence.
    #[must_use]
    pub fn authority_evidence(&self) -> &VerifiedAuthorityEvidenceV2 {
        &self.authority_evidence
    }

    /// Rechecks signature and current provider trust/revocation state.
    pub fn verify_current(
        &self,
        evaluated_at_micros: u64,
        verifier: &dyn AuthorityEvidenceVerifierV2,
    ) -> Result<()> {
        self.authority_evidence.verify_exact(
            self.disposition.evidence_kind(),
            self.ticket.provenance(),
            self.ticket.request().namespace(),
            self.ticket.request().request_id(),
            &managed_copy_terminal_subject(&self.ticket, self.disposition)?,
            evaluated_at_micros,
            verifier,
        )
    }

    /// Converts verified authority evidence into the workflow disposition.
    #[must_use]
    pub fn workflow_disposition(&self) -> ManagedCopyDispositionV2 {
        let evidence = self.authority_evidence.evidence_handle().clone();
        match self.disposition {
            ManagedCopyTerminalDispositionV2::Deleted => {
                ManagedCopyDispositionV2::Deleted { receipt: evidence }
            }
            ManagedCopyTerminalDispositionV2::ProvenAbsent => {
                ManagedCopyDispositionV2::ProvenAbsent { evidence }
            }
            ManagedCopyTerminalDispositionV2::OutsideControl => {
                ManagedCopyDispositionV2::OutsideControl { evidence }
            }
        }
    }
}

impl fmt::Debug for ManagedCopyTerminalEvidenceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedCopyTerminalEvidenceV2")
            .field("ticket", &self.ticket)
            .field("disposition", &self.disposition)
            .field("authority_evidence", &self.authority_evidence)
            .finish()
    }
}

/// Strongly validated provider polling state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ManagedCopyDeletePollV2 {
    /// The provider has accepted the request but has no terminal evidence yet.
    Pending(Box<ManagedCopyDeleteTicketV2>),
    /// The provider returned terminal signed evidence.
    Terminal(Box<ManagedCopyTerminalEvidenceV2>),
}

/// Provider/export/backup deletion adapter boundary.
///
/// Implementations MUST bind a request ID to one exact intent, preserve ticket
/// idempotency, and return verified signed terminal evidence. `OutsideControl`
/// is terminal for polling but can never satisfy hard-delete completion. Direct
/// calls are transport-level only; integration callers use
/// [`CurrentManagedCopyDeletionAdapterV2`] so freshness and returned evidence
/// cannot be forgotten.
pub trait ManagedCopyDeletionAdapterV2: Send + Sync {
    /// Returns authenticated provenance for this adapter deployment.
    fn provenance(&self) -> &AuthorityProvenanceV2;

    /// Durably submits or replays one exact deletion request.
    fn request_delete(
        &self,
        request: &ManagedCopyDeleteRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<ManagedCopyDeleteTicketV2>>;

    /// Polls one exact ticket for signed terminal evidence.
    fn poll_delete(
        &self,
        request: &ManagedCopyDeletePollRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<ManagedCopyDeletePollV2>>;
}

/// Integration-eligible managed-copy view with mandatory per-use trust checks.
pub struct CurrentManagedCopyDeletionAdapterV2<'a> {
    backend: &'a dyn ManagedCopyDeletionAdapterV2,
    provenance_verifier: &'a dyn AuthorityProvenanceVerifierV2,
    evidence_verifier: &'a dyn AuthorityEvidenceVerifierV2,
}

impl<'a> CurrentManagedCopyDeletionAdapterV2<'a> {
    /// Binds an adapter only after a current production provenance decision.
    pub fn bind(
        backend: &'a dyn ManagedCopyDeletionAdapterV2,
        evaluated_at_micros: u64,
        provenance_verifier: &'a dyn AuthorityProvenanceVerifierV2,
        evidence_verifier: &'a dyn AuthorityEvidenceVerifierV2,
    ) -> Result<Self> {
        require_role(backend.provenance(), AuthorityRoleV2::ManagedCopyProvider)?;
        backend
            .provenance()
            .require_current(evaluated_at_micros, provenance_verifier)?;
        Ok(Self {
            backend,
            provenance_verifier,
            evidence_verifier,
        })
    }

    /// Submits an exact deletion only after refreshing production trust.
    pub fn request_delete(
        &self,
        evaluated_at_micros: u64,
        request: &ManagedCopyDeleteRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<ManagedCopyDeleteTicketV2>> {
        self.require_current(evaluated_at_micros)?;
        let outcome = self.backend.request_delete(request)?;
        match &outcome {
            AuthorityOperationOutcomeV2::Applied(ticket)
            | AuthorityOperationOutcomeV2::AlreadyApplied(ticket) => {
                validate_managed_copy_ticket(ticket, request, self.backend.provenance())?;
            }
            AuthorityOperationOutcomeV2::Conflict { .. }
            | AuthorityOperationOutcomeV2::Unavailable => {}
        }
        Ok(outcome)
    }

    /// Polls only after refreshing trust and re-verifies terminal evidence.
    pub fn poll_delete(
        &self,
        evaluated_at_micros: u64,
        request: &ManagedCopyDeletePollRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<ManagedCopyDeletePollV2>> {
        self.require_current(evaluated_at_micros)?;
        let outcome = self.backend.poll_delete(request)?;
        match &outcome {
            AuthorityOperationOutcomeV2::Applied(value)
            | AuthorityOperationOutcomeV2::AlreadyApplied(value) => match value {
                ManagedCopyDeletePollV2::Pending(ticket) => {
                    if ticket.as_ref() != request.ticket() {
                        return Err(SecureStoreError::Integrity(
                            "managed-copy poll returned a substituted pending ticket".to_owned(),
                        ));
                    }
                }
                ManagedCopyDeletePollV2::Terminal(evidence) => {
                    if evidence.ticket() != request.ticket() {
                        return Err(SecureStoreError::Integrity(
                            "managed-copy poll returned evidence for another ticket".to_owned(),
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

impl fmt::Debug for CurrentManagedCopyDeletionAdapterV2<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentManagedCopyDeletionAdapterV2")
            .field("provenance", self.backend.provenance())
            .finish_non_exhaustive()
    }
}

fn validate_managed_copy_ticket(
    ticket: &ManagedCopyDeleteTicketV2,
    request: &ManagedCopyDeleteRequestV2,
    provenance: &AuthorityProvenanceV2,
) -> Result<()> {
    if ticket.provenance() != provenance
        || ticket.request() != request
        || ticket.request_intent_commitment() != &request.intent_commitment()?
    {
        return Err(SecureStoreError::Integrity(
            "managed-copy authority returned a ticket for another request".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn managed_copy_terminal_subject(
    ticket: &ManagedCopyDeleteTicketV2,
    disposition: ManagedCopyTerminalDispositionV2,
) -> Result<StateRootV2> {
    #[derive(Serialize)]
    struct Subject<'a> {
        ticket: &'a ManagedCopyDeleteTicketV2,
        disposition: ManagedCopyTerminalDispositionV2,
    }
    intent_commitment(
        "managed-copy-terminal-evidence-subject-v2",
        &Subject {
            ticket,
            disposition,
        },
    )
}
