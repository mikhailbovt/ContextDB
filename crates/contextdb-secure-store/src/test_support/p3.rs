use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use super::InMemoryKeyAuthorityV2;
use crate::{
    AnchoredCompositeHeadV2, AuthorityEvidenceKindV2, AuthorityEvidenceVerifierV2,
    AuthorityOperationOutcomeV2, AuthorityProvenanceV2, AuthorityRoleV2, AuthorityTicketHandleV2,
    CompositeHeadCasOutcomeV2, CompositeHeadCasRequestV2, CompositeHeadLineageProofV2,
    CompositeHeadLoadOutcomeV2, CompositeHeadLoadRequestV2, CompositeHeadRepositoryV2, DekScopeV2,
    EvidenceHandleV2, HeadAnchorReceiptV2, HeadAnchorV2, HeadMacAuthorityV2, KeyAuthorityV2,
    KeyDescriptorV2, KeyDestroyPollV2, KeyDestroyTicketV2, KeyDestructionEvidenceV2,
    ManagedCopyDeletePollRequestV2, ManagedCopyDeletePollV2, ManagedCopyDeleteRequestV2,
    ManagedCopyDeleteTicketV2, ManagedCopyDeletionAdapterV2, ManagedCopyTerminalDispositionV2,
    ManagedCopyTerminalEvidenceV2, NonProductionAuthorityEvidenceSignerV2, OperationRequestIdV2,
    ProductionKeyAuthorityV2, ProductionKeyCreateRequestV2, ProductionKeyDescribeRequestV2,
    ProductionKeyDestroyPollRequestV2, ProductionKeyDestroyRequestV2, ReceiptSigningKeyRefV2,
    Result, SecureStoreError, StateRootV2, classify_composite_head_load_v2, head_anchor_subject,
    intent_commitment, issue_non_production_evidence, key_destruction_subject,
    managed_copy_terminal_subject, validate_composite_head_cas,
};

/// Volatile keyed-BLAKE3 authority used only to exercise P3 boundary contracts.
///
/// Its provenance is always `NonProduction`; possessing it can never satisfy
/// the production trust gate.
pub struct NonProductionBoundaryAuthorityV2 {
    provenance: AuthorityProvenanceV2,
    signing_key: ReceiptSigningKeyRefV2,
    key: Zeroizing<[u8; 32]>,
}

impl NonProductionBoundaryAuthorityV2 {
    /// Creates a random explicitly non-production boundary authority.
    pub fn random(
        role: AuthorityRoleV2,
        authority_id: impl Into<String>,
        deployment_id: impl Into<String>,
    ) -> Result<Self> {
        let authority_id = authority_id.into();
        let provenance =
            AuthorityProvenanceV2::non_production(role, authority_id.clone(), deployment_id)?;
        let signing_key = ReceiptSigningKeyRefV2::new(format!("{authority_id}-test-key"), 1)?;
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|_| SecureStoreError::CryptographicFailure)?;
        Ok(Self {
            provenance,
            signing_key,
            key,
        })
    }

    /// Returns explicit non-production provenance.
    #[must_use]
    pub fn provenance(&self) -> &AuthorityProvenanceV2 {
        &self.provenance
    }
}

impl std::fmt::Debug for NonProductionBoundaryAuthorityV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NonProductionBoundaryAuthorityV2")
            .field("provenance", &self.provenance)
            .field("signing_key_generation", &self.signing_key.generation())
            .finish_non_exhaustive()
    }
}

impl NonProductionAuthorityEvidenceSignerV2 for NonProductionBoundaryAuthorityV2 {
    fn signing_key(&self) -> Result<ReceiptSigningKeyRefV2> {
        Ok(self.signing_key.clone())
    }

    fn sign_evidence(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(blake3::keyed_hash(&self.key, message).as_bytes().to_vec())
    }
}

impl AuthorityEvidenceVerifierV2 for NonProductionBoundaryAuthorityV2 {
    fn verify_current_provenance(
        &self,
        provenance: &AuthorityProvenanceV2,
        _evaluated_at_micros: u64,
    ) -> Result<()> {
        if provenance == &self.provenance {
            Ok(())
        } else {
            Err(SecureStoreError::CryptographicFailure)
        }
    }

    fn verify_evidence(
        &self,
        provenance: &AuthorityProvenanceV2,
        signing_key: &ReceiptSigningKeyRefV2,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        if provenance != &self.provenance
            || signing_key != &self.signing_key
            || signature.len() != 32
        {
            return Err(SecureStoreError::CryptographicFailure);
        }
        let actual: [u8; 32] = signature
            .try_into()
            .map_err(|_| SecureStoreError::CryptographicFailure)?;
        if blake3::keyed_hash(&self.key, message) != blake3::Hash::from_bytes(actual) {
            return Err(SecureStoreError::CryptographicFailure);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct IdempotentValueV2<T> {
    intent: StateRootV2,
    value: T,
}

#[derive(Default)]
struct NonProductionKeyStateV2 {
    keys: InMemoryKeyAuthorityV2,
    scopes: BTreeMap<DekScopeV2, KeyDescriptorV2>,
    creates: BTreeMap<OperationRequestIdV2, IdempotentValueV2<KeyDescriptorV2>>,
    describes: BTreeMap<OperationRequestIdV2, IdempotentValueV2<KeyDescriptorV2>>,
    destroys: BTreeMap<OperationRequestIdV2, IdempotentValueV2<KeyDestroyTicketV2>>,
    tickets: BTreeMap<AuthorityTicketHandleV2, KeyTicketRecordV2>,
    polls: BTreeMap<OperationRequestIdV2, IdempotentValueV2<KeyDestroyPollV2>>,
}

#[derive(Clone)]
struct KeyTicketRecordV2 {
    ticket: KeyDestroyTicketV2,
    destroyed: Option<KeyDestructionEvidenceV2>,
}

/// Volatile non-production implementation of the asynchronous key boundary.
pub struct NonProductionKeyAuthorityAdapterV2 {
    authority: NonProductionBoundaryAuthorityV2,
    state: Mutex<NonProductionKeyStateV2>,
}

impl NonProductionKeyAuthorityAdapterV2 {
    /// Creates an empty, explicitly non-production adapter.
    pub fn random(
        authority_id: impl Into<String>,
        deployment_id: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            authority: NonProductionBoundaryAuthorityV2::random(
                AuthorityRoleV2::KeyAuthority,
                authority_id,
                deployment_id,
            )?,
            state: Mutex::new(NonProductionKeyStateV2::default()),
        })
    }

    /// Advances one accepted ticket to destroyed and emits signed test evidence.
    pub fn complete_destroy_for_test(
        &self,
        ticket_handle: &AuthorityTicketHandleV2,
        issued_at_micros: u64,
    ) -> Result<KeyDestructionEvidenceV2> {
        let mut state = lock(&self.state)?;
        let record = state
            .tickets
            .get(ticket_handle)
            .cloned()
            .ok_or(SecureStoreError::KeyUnavailable)?;
        if let Some(existing) = record.destroyed {
            return Ok(existing);
        }
        let evidence_handle = EvidenceHandleV2::generate()?;
        let destroyed_descriptor = state.keys.confirm_destroy(
            record.ticket.pending_descriptor().key_handle(),
            record.ticket.pending_descriptor().generation(),
            evidence_handle.clone(),
        )?;
        let subject = key_destruction_subject(&record.ticket, &destroyed_descriptor)?;
        let signed = issue_non_production_evidence(
            AuthorityEvidenceKindV2::KeyDestroyed,
            self.authority.provenance.clone(),
            record.ticket.namespace().clone(),
            record.ticket.request_id().clone(),
            subject,
            issued_at_micros,
            evidence_handle,
            &self.authority,
        )?;
        let evidence = KeyDestructionEvidenceV2::from_verified(
            record.ticket.clone(),
            destroyed_descriptor.clone(),
            signed,
        )?;
        let ticket_record = state
            .tickets
            .get_mut(ticket_handle)
            .ok_or(SecureStoreError::KeyUnavailable)?;
        ticket_record.destroyed = Some(evidence.clone());
        if let Some(scope_descriptor) = state.scopes.get_mut(destroyed_descriptor.scope()) {
            *scope_descriptor = destroyed_descriptor;
        }
        Ok(evidence)
    }
}

impl std::fmt::Debug for NonProductionKeyAuthorityAdapterV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let record_count = self
            .state
            .lock()
            .map(|state| state.scopes.len())
            .unwrap_or_default();
        formatter
            .debug_struct("NonProductionKeyAuthorityAdapterV2")
            .field("provenance", &self.authority.provenance)
            .field("record_count", &record_count)
            .finish_non_exhaustive()
    }
}

impl AuthorityEvidenceVerifierV2 for NonProductionKeyAuthorityAdapterV2 {
    fn verify_current_provenance(
        &self,
        provenance: &AuthorityProvenanceV2,
        evaluated_at_micros: u64,
    ) -> Result<()> {
        self.authority
            .verify_current_provenance(provenance, evaluated_at_micros)
    }

    fn verify_evidence(
        &self,
        provenance: &AuthorityProvenanceV2,
        signing_key: &ReceiptSigningKeyRefV2,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        self.authority
            .verify_evidence(provenance, signing_key, message, signature)
    }
}

impl ProductionKeyAuthorityV2 for NonProductionKeyAuthorityAdapterV2 {
    fn provenance(&self) -> &AuthorityProvenanceV2 {
        self.authority.provenance()
    }

    fn create_or_get(
        &self,
        request: &ProductionKeyCreateRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDescriptorV2>> {
        let intent = request.intent_commitment()?;
        let mut state = lock(&self.state)?;
        if let Some(existing) = state.creates.get(request.request_id()) {
            return Ok(if existing.intent == intent {
                AuthorityOperationOutcomeV2::AlreadyApplied(existing.value.clone())
            } else {
                AuthorityOperationOutcomeV2::Conflict {
                    existing_commitment: existing.intent.clone(),
                }
            });
        }
        if let Some(existing) = state.scopes.get(request.scope()).cloned() {
            state.creates.insert(
                request.request_id().clone(),
                IdempotentValueV2 {
                    intent,
                    value: existing.clone(),
                },
            );
            return Ok(AuthorityOperationOutcomeV2::AlreadyApplied(existing));
        }
        let descriptor = state.keys.create_random_dek(request.scope().clone())?;
        request.validate_response(&descriptor)?;
        state
            .scopes
            .insert(request.scope().clone(), descriptor.clone());
        state.creates.insert(
            request.request_id().clone(),
            IdempotentValueV2 {
                intent,
                value: descriptor.clone(),
            },
        );
        Ok(AuthorityOperationOutcomeV2::Applied(descriptor))
    }

    fn describe_strongly_consistent(
        &self,
        request: &ProductionKeyDescribeRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDescriptorV2>> {
        let intent = request.intent_commitment()?;
        let mut state = lock(&self.state)?;
        if let Some(existing) = state.describes.get(request.request_id()) {
            return Ok(if existing.intent == intent {
                AuthorityOperationOutcomeV2::AlreadyApplied(existing.value.clone())
            } else {
                AuthorityOperationOutcomeV2::Conflict {
                    existing_commitment: existing.intent.clone(),
                }
            });
        }
        let descriptor = state.keys.descriptor(request.key_handle())?;
        request.validate_response(&descriptor)?;
        state.describes.insert(
            request.request_id().clone(),
            IdempotentValueV2 {
                intent,
                value: descriptor.clone(),
            },
        );
        Ok(AuthorityOperationOutcomeV2::Applied(descriptor))
    }

    fn request_destroy(
        &self,
        request: &ProductionKeyDestroyRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDestroyTicketV2>> {
        let intent = request.intent_commitment()?;
        let mut state = lock(&self.state)?;
        if let Some(existing) = state.destroys.get(request.request_id()) {
            return Ok(if existing.intent == intent {
                AuthorityOperationOutcomeV2::AlreadyApplied(existing.value.clone())
            } else {
                AuthorityOperationOutcomeV2::Conflict {
                    existing_commitment: existing.intent.clone(),
                }
            });
        }
        let current = state
            .keys
            .descriptor(request.expected_descriptor().key_handle())?;
        if current != *request.expected_descriptor() {
            return Ok(AuthorityOperationOutcomeV2::Conflict {
                existing_commitment: intent_commitment(
                    "production-key-current-descriptor-v2",
                    &current,
                )?,
            });
        }
        let pending = state.keys.request_destroy(
            request.expected_descriptor().key_handle(),
            request.expected_descriptor().generation(),
        )?;
        let ticket = KeyDestroyTicketV2::authority_accepted(
            AuthorityTicketHandleV2::generate()?,
            request,
            self.authority.provenance.clone(),
            pending.clone(),
        )?;
        if let Some(scope_descriptor) = state.scopes.get_mut(pending.scope()) {
            *scope_descriptor = pending;
        }
        state.tickets.insert(
            ticket.ticket_handle().clone(),
            KeyTicketRecordV2 {
                ticket: ticket.clone(),
                destroyed: None,
            },
        );
        state.destroys.insert(
            request.request_id().clone(),
            IdempotentValueV2 {
                intent,
                value: ticket.clone(),
            },
        );
        Ok(AuthorityOperationOutcomeV2::Applied(ticket))
    }

    fn poll_destroy(
        &self,
        request: &ProductionKeyDestroyPollRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDestroyPollV2>> {
        let intent = request.intent_commitment()?;
        let mut state = lock(&self.state)?;
        if let Some(existing) = state.polls.get(request.request_id()) {
            return Ok(if existing.intent == intent {
                AuthorityOperationOutcomeV2::AlreadyApplied(existing.value.clone())
            } else {
                AuthorityOperationOutcomeV2::Conflict {
                    existing_commitment: existing.intent.clone(),
                }
            });
        }
        let record = state
            .tickets
            .get(request.ticket().ticket_handle())
            .cloned()
            .ok_or(SecureStoreError::KeyUnavailable)?;
        if &record.ticket != request.ticket() {
            return Ok(AuthorityOperationOutcomeV2::Conflict {
                existing_commitment: record.ticket.request_intent_commitment().clone(),
            });
        }
        let value = match record.destroyed {
            Some(evidence) => KeyDestroyPollV2::Destroyed(Box::new(evidence)),
            None => KeyDestroyPollV2::pending(
                record.ticket.clone(),
                record.ticket.pending_descriptor().clone(),
            )?,
        };
        state.polls.insert(
            request.request_id().clone(),
            IdempotentValueV2 {
                intent,
                value: value.clone(),
            },
        );
        Ok(AuthorityOperationOutcomeV2::Applied(value))
    }
}

#[derive(Default)]
struct NonProductionHeadRepositoryStateV2 {
    current: Option<AnchoredCompositeHeadV2>,
    history: BTreeMap<u64, HeadAnchorReceiptV2>,
    requests: BTreeMap<OperationRequestIdV2, IdempotentValueV2<AnchoredCompositeHeadV2>>,
}

/// Volatile repository exercising exact initialization, CAS, and lineage rules.
pub struct NonProductionCompositeHeadRepositoryV2 {
    authority: NonProductionBoundaryAuthorityV2,
    mac_authority: Arc<dyn HeadMacAuthorityV2 + Send + Sync>,
    state: Mutex<NonProductionHeadRepositoryStateV2>,
}

impl NonProductionCompositeHeadRepositoryV2 {
    /// Creates an empty repository distinct from the supplied head MAC authority.
    pub fn random(
        authority_id: impl Into<String>,
        deployment_id: impl Into<String>,
        mac_authority: Arc<dyn HeadMacAuthorityV2 + Send + Sync>,
    ) -> Result<Self> {
        Ok(Self {
            authority: NonProductionBoundaryAuthorityV2::random(
                AuthorityRoleV2::CompositeHeadRepository,
                authority_id,
                deployment_id,
            )?,
            mac_authority,
            state: Mutex::new(NonProductionHeadRepositoryStateV2::default()),
        })
    }

    /// Returns a test-only copy of signed receipts after `sequence`.
    pub fn lineage_receipts_after_for_test(
        &self,
        sequence: u64,
    ) -> Result<Vec<HeadAnchorReceiptV2>> {
        let state = lock(&self.state)?;
        Ok(state
            .history
            .range((sequence.saturating_add(1))..)
            .map(|(_, receipt)| receipt.clone())
            .collect())
    }
}

impl std::fmt::Debug for NonProductionCompositeHeadRepositoryV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sequence = self
            .state
            .lock()
            .ok()
            .and_then(|state| state.current.as_ref().map(|value| value.head().sequence()));
        formatter
            .debug_struct("NonProductionCompositeHeadRepositoryV2")
            .field("provenance", &self.authority.provenance)
            .field("current_sequence", &sequence)
            .finish_non_exhaustive()
    }
}

impl AuthorityEvidenceVerifierV2 for NonProductionCompositeHeadRepositoryV2 {
    fn verify_current_provenance(
        &self,
        provenance: &AuthorityProvenanceV2,
        evaluated_at_micros: u64,
    ) -> Result<()> {
        self.authority
            .verify_current_provenance(provenance, evaluated_at_micros)
    }

    fn verify_evidence(
        &self,
        provenance: &AuthorityProvenanceV2,
        signing_key: &ReceiptSigningKeyRefV2,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        self.authority
            .verify_evidence(provenance, signing_key, message, signature)
    }
}

impl CompositeHeadRepositoryV2 for NonProductionCompositeHeadRepositoryV2 {
    fn provenance(&self) -> &AuthorityProvenanceV2 {
        self.authority.provenance()
    }

    fn load(&self, request: &CompositeHeadLoadRequestV2) -> Result<CompositeHeadLoadOutcomeV2> {
        let state = lock(&self.state)?;
        let observed = state.current.clone();
        if let Some(current) = &observed {
            if current.head().namespace() != request.namespace() {
                return Err(SecureStoreError::Integrity(
                    "repository load namespace differs from stored head".to_owned(),
                ));
            }
            current
                .head()
                .verify(request.namespace(), self.mac_authority.as_ref())?;
        }
        let lineage = match (request.expected_anchor(), observed.as_ref()) {
            (Some(expected), Some(current))
                if current.anchor().sequence() > expected.sequence() =>
            {
                let receipts = state
                    .history
                    .range((expected.sequence().saturating_add(1))..=current.anchor().sequence())
                    .map(|(_, receipt)| receipt.clone())
                    .collect::<Vec<_>>();
                CompositeHeadLineageProofV2::try_new(expected, current, receipts).ok()
            }
            _ => None,
        };
        classify_composite_head_load_v2(request.expected_anchor(), observed, lineage)
    }

    fn compare_and_swap(
        &self,
        request: &CompositeHeadCasRequestV2,
    ) -> Result<CompositeHeadCasOutcomeV2> {
        let intent = request.intent_commitment()?;
        let mut state = lock(&self.state)?;
        if let Some(existing) = state.requests.get(request.request_id()) {
            return Ok(if existing.intent == intent {
                CompositeHeadCasOutcomeV2::AlreadyAnchored(existing.value.clone())
            } else {
                CompositeHeadCasOutcomeV2::Conflict {
                    current: state.current.as_ref().map(|value| value.anchor().clone()),
                }
            });
        }
        let current_anchor = state.current.as_ref().map(|value| value.anchor().clone());
        match (request.expected_anchor(), current_anchor.as_ref()) {
            (None, None) => {
                request
                    .next_head()
                    .verify(request.next_head().namespace(), self.mac_authority.as_ref())?;
            }
            (Some(expected), Some(current)) if expected == current => {
                let current_head = state.current.as_ref().ok_or_else(|| {
                    SecureStoreError::StateConflict("repository current head vanished".to_owned())
                })?;
                validate_composite_head_cas(
                    &current_head.head().cas_token(),
                    current_head.head().namespace(),
                    current_head.head(),
                    request.next_head(),
                    self.mac_authority.as_ref(),
                )?;
            }
            (Some(expected), Some(current))
                if expected.sequence() == current.sequence()
                    && expected.head_commitment() != current.head_commitment() =>
            {
                return Ok(CompositeHeadCasOutcomeV2::Divergence {
                    sequence: expected.sequence(),
                    expected_commitment: expected.head_commitment().clone(),
                    observed_commitment: current.head_commitment().clone(),
                });
            }
            _ => {
                return Ok(CompositeHeadCasOutcomeV2::Conflict {
                    current: current_anchor,
                });
            }
        }
        let anchor = HeadAnchorV2::from_head(request.next_head())?;
        let subject = head_anchor_subject(request.expected_anchor(), &anchor)?;
        let evidence_handle = EvidenceHandleV2::generate()?;
        let evidence = issue_non_production_evidence(
            AuthorityEvidenceKindV2::CompositeHeadAnchored,
            self.authority.provenance.clone(),
            request.next_head().namespace().clone(),
            request.request_id().clone(),
            subject,
            request.next_head().sequence(),
            evidence_handle,
            &self.authority,
        )?;
        let receipt = HeadAnchorReceiptV2::from_verified(
            anchor.clone(),
            request.expected_anchor().cloned(),
            self.authority.provenance.clone(),
            evidence,
        )?;
        let anchored =
            AnchoredCompositeHeadV2::try_new(request.next_head().clone(), receipt.clone())?;
        state.history.insert(anchor.sequence(), receipt);
        state.current = Some(anchored.clone());
        state.requests.insert(
            request.request_id().clone(),
            IdempotentValueV2 {
                intent,
                value: anchored.clone(),
            },
        );
        Ok(CompositeHeadCasOutcomeV2::Applied(anchored))
    }
}

#[derive(Clone)]
struct ManagedCopyTicketRecordV2 {
    ticket: ManagedCopyDeleteTicketV2,
    terminal: Option<ManagedCopyTerminalEvidenceV2>,
}

#[derive(Default)]
struct NonProductionManagedCopyStateV2 {
    requests: BTreeMap<OperationRequestIdV2, IdempotentValueV2<ManagedCopyDeleteTicketV2>>,
    tickets: BTreeMap<AuthorityTicketHandleV2, ManagedCopyTicketRecordV2>,
    polls: BTreeMap<OperationRequestIdV2, IdempotentValueV2<ManagedCopyDeletePollV2>>,
}

/// Volatile non-production provider/export/backup deletion adapter.
pub struct NonProductionManagedCopyDeletionAdapterV2 {
    authority: NonProductionBoundaryAuthorityV2,
    state: Mutex<NonProductionManagedCopyStateV2>,
}

impl NonProductionManagedCopyDeletionAdapterV2 {
    /// Creates an empty adapter with explicit non-production provenance.
    pub fn random(
        authority_id: impl Into<String>,
        deployment_id: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            authority: NonProductionBoundaryAuthorityV2::random(
                AuthorityRoleV2::ManagedCopyProvider,
                authority_id,
                deployment_id,
            )?,
            state: Mutex::new(NonProductionManagedCopyStateV2::default()),
        })
    }

    /// Emits signed test evidence for a terminal provider outcome.
    pub fn mark_terminal_for_test(
        &self,
        ticket_handle: &AuthorityTicketHandleV2,
        disposition: ManagedCopyTerminalDispositionV2,
        issued_at_micros: u64,
    ) -> Result<ManagedCopyTerminalEvidenceV2> {
        let mut state = lock(&self.state)?;
        let record = state.tickets.get(ticket_handle).cloned().ok_or_else(|| {
            SecureStoreError::StateConflict("managed-copy ticket is unknown".to_owned())
        })?;
        if let Some(existing) = record.terminal {
            if existing.disposition() == disposition {
                return Ok(existing);
            }
            return Err(SecureStoreError::StateConflict(
                "managed-copy ticket already has a different terminal outcome".to_owned(),
            ));
        }
        let subject = managed_copy_terminal_subject(&record.ticket, disposition)?;
        let evidence = issue_non_production_evidence(
            disposition_kind(disposition),
            self.authority.provenance.clone(),
            record.ticket.request().namespace().clone(),
            record.ticket.request().request_id().clone(),
            subject,
            issued_at_micros,
            EvidenceHandleV2::generate()?,
            &self.authority,
        )?;
        let terminal = ManagedCopyTerminalEvidenceV2::from_verified(
            record.ticket.clone(),
            disposition,
            evidence,
        )?;
        let stored = state.tickets.get_mut(ticket_handle).ok_or_else(|| {
            SecureStoreError::StateConflict("managed-copy ticket vanished".to_owned())
        })?;
        stored.terminal = Some(terminal.clone());
        Ok(terminal)
    }
}

impl std::fmt::Debug for NonProductionManagedCopyDeletionAdapterV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ticket_count = self
            .state
            .lock()
            .map(|state| state.tickets.len())
            .unwrap_or_default();
        formatter
            .debug_struct("NonProductionManagedCopyDeletionAdapterV2")
            .field("provenance", &self.authority.provenance)
            .field("ticket_count", &ticket_count)
            .finish_non_exhaustive()
    }
}

impl AuthorityEvidenceVerifierV2 for NonProductionManagedCopyDeletionAdapterV2 {
    fn verify_current_provenance(
        &self,
        provenance: &AuthorityProvenanceV2,
        evaluated_at_micros: u64,
    ) -> Result<()> {
        self.authority
            .verify_current_provenance(provenance, evaluated_at_micros)
    }

    fn verify_evidence(
        &self,
        provenance: &AuthorityProvenanceV2,
        signing_key: &ReceiptSigningKeyRefV2,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        self.authority
            .verify_evidence(provenance, signing_key, message, signature)
    }
}

impl ManagedCopyDeletionAdapterV2 for NonProductionManagedCopyDeletionAdapterV2 {
    fn provenance(&self) -> &AuthorityProvenanceV2 {
        self.authority.provenance()
    }

    fn request_delete(
        &self,
        request: &ManagedCopyDeleteRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<ManagedCopyDeleteTicketV2>> {
        let intent = request.intent_commitment()?;
        let mut state = lock(&self.state)?;
        if let Some(existing) = state.requests.get(request.request_id()) {
            return Ok(if existing.intent == intent {
                AuthorityOperationOutcomeV2::AlreadyApplied(existing.value.clone())
            } else {
                AuthorityOperationOutcomeV2::Conflict {
                    existing_commitment: existing.intent.clone(),
                }
            });
        }
        let ticket = ManagedCopyDeleteTicketV2::authority_accepted(
            AuthorityTicketHandleV2::generate()?,
            self.authority.provenance.clone(),
            request.clone(),
        )?;
        state.tickets.insert(
            ticket.ticket_handle().clone(),
            ManagedCopyTicketRecordV2 {
                ticket: ticket.clone(),
                terminal: None,
            },
        );
        state.requests.insert(
            request.request_id().clone(),
            IdempotentValueV2 {
                intent,
                value: ticket.clone(),
            },
        );
        Ok(AuthorityOperationOutcomeV2::Applied(ticket))
    }

    fn poll_delete(
        &self,
        request: &ManagedCopyDeletePollRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<ManagedCopyDeletePollV2>> {
        let intent = intent_commitment("managed-copy-delete-poll-v2", request)?;
        let mut state = lock(&self.state)?;
        if let Some(existing) = state.polls.get(request.request_id()) {
            return Ok(if existing.intent == intent {
                AuthorityOperationOutcomeV2::AlreadyApplied(existing.value.clone())
            } else {
                AuthorityOperationOutcomeV2::Conflict {
                    existing_commitment: existing.intent.clone(),
                }
            });
        }
        let record = state
            .tickets
            .get(request.ticket().ticket_handle())
            .cloned()
            .ok_or_else(|| {
                SecureStoreError::StateConflict("managed-copy ticket is unknown".to_owned())
            })?;
        if &record.ticket != request.ticket() {
            return Ok(AuthorityOperationOutcomeV2::Conflict {
                existing_commitment: record.ticket.request_intent_commitment().clone(),
            });
        }
        let value = match record.terminal {
            Some(terminal) => ManagedCopyDeletePollV2::Terminal(Box::new(terminal)),
            None => ManagedCopyDeletePollV2::Pending(Box::new(record.ticket)),
        };
        state.polls.insert(
            request.request_id().clone(),
            IdempotentValueV2 {
                intent,
                value: value.clone(),
            },
        );
        Ok(AuthorityOperationOutcomeV2::Applied(value))
    }
}

const fn disposition_kind(
    disposition: ManagedCopyTerminalDispositionV2,
) -> AuthorityEvidenceKindV2 {
    match disposition {
        ManagedCopyTerminalDispositionV2::Deleted => AuthorityEvidenceKindV2::ManagedCopyDeleted,
        ManagedCopyTerminalDispositionV2::ProvenAbsent => {
            AuthorityEvidenceKindV2::ManagedCopyProvenAbsent
        }
        ManagedCopyTerminalDispositionV2::OutsideControl => {
            AuthorityEvidenceKindV2::ManagedCopyOutsideControl
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| SecureStoreError::StateConflict("test authority lock poisoned".to_owned()))
}
