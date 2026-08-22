use std::fmt;

use crate::{
    AuthorityEvidenceVerifierV2, DeletionClosureClassV2, DeletionTargetDispositionV2,
    DeletionTargetHandleV2, DeletionWorkflowStateV2, DeletionWorkflowV2, EvidenceHandleV2,
    ManagedCopyCatalogCommitmentsV2, ManagedCopyDeleteRequestV2, ManagedCopyDeleteTicketV2,
    ManagedCopyDispositionV2, ManagedCopyTerminalEvidenceV2, OperationRequestIdV2, Result,
    SecureStoreError,
};

/// External durability boundary for a managed-copy deletion intent before any
/// provider/export/backup I/O.
pub trait ManagedCopyRequestPersistenceVerifierV2 {
    /// Verifies durable recovery of the exact idempotent request and returns a
    /// stable opaque audit handle.
    fn verify_persisted_request(
        &self,
        request: &ManagedCopyDeleteRequestV2,
        evaluated_at_micros: u64,
    ) -> Result<EvidenceHandleV2>;
}

/// In-process capability proving that the exact managed-copy request crossed
/// its pre-I/O durability boundary.
///
/// This wrapper is intentionally not serializable. Recovery must decode the
/// bounded P3 request and re-run the external persistence verification.
#[derive(Clone, Eq, PartialEq)]
pub struct PersistedManagedCopyDeleteRequestV2 {
    request: ManagedCopyDeleteRequestV2,
    persistence_evidence: EvidenceHandleV2,
}

impl PersistedManagedCopyDeleteRequestV2 {
    /// Returns the exact request that may now be submitted idempotently.
    #[must_use]
    pub fn request(&self) -> &ManagedCopyDeleteRequestV2 {
        &self.request
    }

    /// Returns the opaque local request-persistence audit handle.
    #[must_use]
    pub fn persistence_evidence(&self) -> &EvidenceHandleV2 {
        &self.persistence_evidence
    }
}

impl fmt::Debug for PersistedManagedCopyDeleteRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedManagedCopyDeleteRequestV2")
            .field("request", &self.request)
            .field("persistence_evidence", &"[OPAQUE]")
            .finish()
    }
}

/// External durability boundary for an accepted managed-copy authority ticket.
///
/// The verifier must prove that the exact ticket is recoverably persisted before
/// returning a stable opaque audit handle. Re-verifying the same exact ticket
/// must return the same handle. This crate never manufactures such a handle
/// from a provider ticket or treats submission as deletion evidence.
pub trait ManagedCopyTicketPersistenceVerifierV2 {
    /// Verifies durable local persistence of one exact accepted ticket.
    fn verify_persisted_ticket(
        &self,
        ticket: &ManagedCopyDeleteTicketV2,
        evaluated_at_micros: u64,
    ) -> Result<EvidenceHandleV2>;
}

/// Builds one exact provider/export/backup deletion request from the immutable
/// workflow closure and its frozen P4 managed-copy catalog commitments, then
/// requires durable recovery proof before the request may cross external I/O.
pub fn prepare_persisted_managed_copy_delete_request_v2(
    workflow: &DeletionWorkflowV2,
    target: DeletionTargetHandleV2,
    request_id: OperationRequestIdV2,
    commitments: &ManagedCopyCatalogCommitmentsV2,
    evaluated_at_micros: u64,
    persistence_verifier: &dyn ManagedCopyRequestPersistenceVerifierV2,
) -> Result<PersistedManagedCopyDeleteRequestV2> {
    if !matches!(
        workflow.state(),
        DeletionWorkflowStateV2::Purging | DeletionWorkflowStateV2::AwaitingExternal
    ) {
        return Err(SecureStoreError::StateConflict(
            "managed-copy deletion can start only after durable suppression".to_owned(),
        ));
    }
    let class = workflow.inventory().class_of(&target).ok_or_else(|| {
        SecureStoreError::DeletionIncomplete(
            "managed-copy target is outside the authoritative closure".to_owned(),
        )
    })?;
    if !class.is_managed_copy() {
        return Err(SecureStoreError::Integrity(
            "local deletion target cannot use a managed-copy adapter".to_owned(),
        ));
    }
    let commitment = commitments
        .commitments()
        .iter()
        .find(|value| value.class() == class)
        .ok_or_else(|| {
            SecureStoreError::DeletionIncomplete(
                "managed-copy inventory commitment is missing".to_owned(),
            )
        })?;
    let request = ManagedCopyDeleteRequestV2::new(
        request_id,
        workflow.namespace().clone(),
        workflow.handle().clone(),
        target,
        class,
        commitment.inventory_generation(),
        commitment.inventory_root().clone(),
    )?;
    let persistence_evidence =
        persistence_verifier.verify_persisted_request(&request, evaluated_at_micros)?;
    Ok(PersistedManagedCopyDeleteRequestV2 {
        request,
        persistence_evidence,
    })
}

/// Records `DeletionRequested` only after the exact authority ticket is
/// independently proven durable and recoverable.
pub fn record_persisted_managed_copy_ticket_v2(
    workflow: &mut DeletionWorkflowV2,
    expected_revision: u64,
    at_micros: u64,
    persisted_request: &PersistedManagedCopyDeleteRequestV2,
    ticket: &ManagedCopyDeleteTicketV2,
    evaluated_at_micros: u64,
    persistence_verifier: &dyn ManagedCopyTicketPersistenceVerifierV2,
) -> Result<()> {
    let request = persisted_request.request();
    require_request_matches_workflow(workflow, request)?;
    if ticket.request() != request
        || ticket.request_intent_commitment() != &request.intent_commitment()?
    {
        return Err(SecureStoreError::Integrity(
            "managed-copy ticket does not bind the exact workflow request".to_owned(),
        ));
    }
    let evidence = persistence_verifier.verify_persisted_ticket(ticket, evaluated_at_micros)?;
    workflow.record_disposition(
        expected_revision,
        at_micros,
        request.target().clone(),
        DeletionTargetDispositionV2::Managed(ManagedCopyDispositionV2::DeletionRequested {
            request: evidence,
        }),
    )
}

/// Re-verifies current authority trust and signed terminal evidence before
/// advancing the exact workflow target. `OutsideControl` remains incomplete by
/// construction and therefore cannot satisfy closure verification.
pub fn record_managed_copy_terminal_evidence_v2(
    workflow: &mut DeletionWorkflowV2,
    expected_revision: u64,
    at_micros: u64,
    terminal: &ManagedCopyTerminalEvidenceV2,
    evaluated_at_micros: u64,
    persistence_verifier: &dyn ManagedCopyTicketPersistenceVerifierV2,
    evidence_verifier: &dyn AuthorityEvidenceVerifierV2,
) -> Result<()> {
    let request = terminal.ticket().request();
    require_request_matches_workflow(workflow, request)?;
    let persisted_ticket =
        persistence_verifier.verify_persisted_ticket(terminal.ticket(), evaluated_at_micros)?;
    let requested =
        DeletionTargetDispositionV2::Managed(ManagedCopyDispositionV2::DeletionRequested {
            request: persisted_ticket,
        });
    let terminal_disposition =
        DeletionTargetDispositionV2::Managed(terminal.workflow_disposition());
    let current = workflow.dispositions().get(request.target());
    if current != Some(&requested) && current != Some(&terminal_disposition) {
        return Err(SecureStoreError::Integrity(
            "terminal managed-copy evidence does not match the durably recorded ticket".to_owned(),
        ));
    }
    terminal.verify_current(evaluated_at_micros, evidence_verifier)?;
    workflow.record_disposition(
        expected_revision,
        at_micros,
        request.target().clone(),
        terminal_disposition,
    )
}

fn require_request_matches_workflow(
    workflow: &DeletionWorkflowV2,
    request: &ManagedCopyDeleteRequestV2,
) -> Result<()> {
    if request.namespace() != workflow.namespace()
        || request.deletion() != workflow.handle()
        || workflow.inventory().class_of(request.target()) != Some(request.class())
        || !request.class().is_managed_copy()
    {
        return Err(SecureStoreError::Integrity(
            "managed-copy request differs from the authoritative workflow closure".to_owned(),
        ));
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "keeps the authoritative managed class set visible to rustdoc"
)]
const MANAGED_CLASSES: [DeletionClosureClassV2; 3] = [
    DeletionClosureClassV2::ProviderCopy,
    DeletionClosureClassV2::Export,
    DeletionClosureClassV2::Backup,
];
