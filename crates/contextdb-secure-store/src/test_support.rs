//! Deliberately non-production authorities used to exercise invariants.
//!
//! These in-memory authorities have no durable anti-rollback or hardware trust
//! boundary. They must never be treated as production KMS/HSM authenticity.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::{
    DekScopeV2, DeletionClosureClassV2, DeletionEvidenceVerifierV2, DeletionHandleV2,
    DeletionReceiptSignerV2, DeletionReceiptVerifierV2, DeletionTargetDispositionV2,
    DeletionTargetHandleV2, EvidenceHandleV2, HeadMacAuthorityV2, HeadMacKeyRefV2, HeadMacTagV2,
    KeyAuthorityV2, KeyDescriptorV2, KeyHandleV2, KeyLifecycleV2, ReceiptSigningKeyRefV2, Result,
    SealedPayloadV2, SecureStoreError, StateNamespaceV2, StateRootV2,
    SuppressionCommitmentVerifierV2,
};

mod p3;

pub use p3::*;

struct InMemoryKeyRecord {
    descriptor: KeyDescriptorV2,
    key: Option<Zeroizing<[u8; 32]>>,
}

/// In-memory random-DEK authority for tests only.
#[derive(Default)]
pub struct InMemoryKeyAuthorityV2 {
    records: BTreeMap<KeyHandleV2, InMemoryKeyRecord>,
}

impl std::fmt::Debug for InMemoryKeyAuthorityV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InMemoryKeyAuthorityV2")
            .field("record_count", &self.records.len())
            .finish_non_exhaustive()
    }
}

impl InMemoryKeyAuthorityV2 {
    fn active_record(&self, descriptor: &KeyDescriptorV2) -> Result<&InMemoryKeyRecord> {
        descriptor.validate()?;
        let record = self
            .records
            .get(descriptor.key_handle())
            .ok_or(SecureStoreError::KeyUnavailable)?;
        if &record.descriptor != descriptor
            || record.descriptor.lifecycle() != KeyLifecycleV2::Active
            || record.key.is_none()
        {
            return Err(SecureStoreError::KeyUnavailable);
        }
        Ok(record)
    }
}

impl KeyAuthorityV2 for InMemoryKeyAuthorityV2 {
    fn create_random_dek(&mut self, scope: DekScopeV2) -> Result<KeyDescriptorV2> {
        if self
            .records
            .values()
            .any(|record| record.descriptor.scope() == &scope)
        {
            return Err(SecureStoreError::StateConflict(
                "test authority refuses a second DEK for the same object scope".to_owned(),
            ));
        }
        let mut key_bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(key_bytes.as_mut()).map_err(|_| SecureStoreError::CryptographicFailure)?;
        let key_handle = (0..8)
            .find_map(|_| {
                let candidate = KeyHandleV2::generate().ok()?;
                (!self.records.contains_key(&candidate)).then_some(candidate)
            })
            .ok_or(SecureStoreError::CryptographicFailure)?;
        let descriptor = KeyDescriptorV2::authority_active(key_handle.clone(), scope)?;
        self.records.insert(
            key_handle,
            InMemoryKeyRecord {
                descriptor: descriptor.clone(),
                key: Some(key_bytes),
            },
        );
        Ok(descriptor)
    }

    fn descriptor(&self, key_handle: &KeyHandleV2) -> Result<KeyDescriptorV2> {
        self.records
            .get(key_handle)
            .map(|record| record.descriptor.clone())
            .ok_or(SecureStoreError::KeyUnavailable)
    }

    fn seal(
        &self,
        key: &KeyDescriptorV2,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedPayloadV2> {
        if plaintext.is_empty() || associated_data.is_empty() {
            return Err(SecureStoreError::InvalidInput(
                "test sealing requires non-empty content and associated data".to_owned(),
            ));
        }
        let record = self.active_record(key)?;
        let key_bytes = record
            .key
            .as_ref()
            .ok_or(SecureStoreError::KeyUnavailable)?;
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| SecureStoreError::CryptographicFailure)?;
        let cipher = XChaCha20Poly1305::new(&Key::from(**key_bytes));
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| SecureStoreError::CryptographicFailure)?;
        SealedPayloadV2::try_new(nonce.to_vec(), ciphertext)
    }

    fn open(
        &self,
        key: &KeyDescriptorV2,
        payload: &SealedPayloadV2,
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if associated_data.is_empty() {
            return Err(SecureStoreError::InvalidInput(
                "test opening requires associated data".to_owned(),
            ));
        }
        let record = self.active_record(key)?;
        let key_bytes = record
            .key
            .as_ref()
            .ok_or(SecureStoreError::KeyUnavailable)?;
        let nonce: [u8; 24] = payload.nonce().try_into().map_err(|_| {
            SecureStoreError::Integrity("sealed payload nonce is invalid".to_owned())
        })?;
        let cipher = XChaCha20Poly1305::new(&Key::from(**key_bytes));
        let plaintext = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: payload.ciphertext(),
                    aad: associated_data,
                },
            )
            .map_err(|_| SecureStoreError::CryptographicFailure)?;
        Ok(Zeroizing::new(plaintext))
    }

    fn request_destroy(
        &mut self,
        key_handle: &KeyHandleV2,
        expected_generation: u64,
    ) -> Result<KeyDescriptorV2> {
        let record = self
            .records
            .get_mut(key_handle)
            .ok_or(SecureStoreError::KeyUnavailable)?;
        if record.descriptor.generation() != expected_generation {
            return Err(SecureStoreError::StateConflict(
                "key generation is stale".to_owned(),
            ));
        }
        record.descriptor = record.descriptor.authority_destroy_pending()?;
        Ok(record.descriptor.clone())
    }

    fn confirm_destroy(
        &mut self,
        key_handle: &KeyHandleV2,
        expected_generation: u64,
        authority_evidence: EvidenceHandleV2,
    ) -> Result<KeyDescriptorV2> {
        let record = self
            .records
            .get_mut(key_handle)
            .ok_or(SecureStoreError::KeyUnavailable)?;
        if record.descriptor.generation() != expected_generation {
            return Err(SecureStoreError::StateConflict(
                "key generation is stale".to_owned(),
            ));
        }
        let destroyed = record.descriptor.authority_destroyed(authority_evidence)?;
        record.key = None;
        record.descriptor = destroyed;
        Ok(record.descriptor.clone())
    }
}

/// In-memory keyed-BLAKE3 head authority for tests only.
pub struct InMemoryHeadMacAuthorityV2 {
    key_id: String,
    active_generation: u64,
    keys: BTreeMap<u64, Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for InMemoryHeadMacAuthorityV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InMemoryHeadMacAuthorityV2")
            .field("key_id", &self.key_id)
            .field("active_generation", &self.active_generation)
            .field("retained_generation_count", &self.keys.len())
            .finish()
    }
}

impl InMemoryHeadMacAuthorityV2 {
    /// Creates an authority with random generation-one key bytes.
    pub fn random(key_id: impl Into<String>) -> Result<Self> {
        let key_id = key_id.into();
        HeadMacKeyRefV2::new(key_id.clone(), 1)?;
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|_| SecureStoreError::CryptographicFailure)?;
        Ok(Self {
            key_id,
            active_generation: 1,
            keys: BTreeMap::from([(1, key)]),
        })
    }

    /// Adds a random exact successor generation while retaining old verification keys.
    pub fn rotate(&mut self) -> Result<HeadMacKeyRefV2> {
        let generation = self.active_generation.checked_add(1).ok_or_else(|| {
            SecureStoreError::StateConflict("test MAC generation exhausted".to_owned())
        })?;
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|_| SecureStoreError::CryptographicFailure)?;
        self.keys.insert(generation, key);
        self.active_generation = generation;
        HeadMacKeyRefV2::new(self.key_id.clone(), generation)
    }
}

impl HeadMacAuthorityV2 for InMemoryHeadMacAuthorityV2 {
    fn active_key(&self) -> Result<HeadMacKeyRefV2> {
        HeadMacKeyRefV2::new(self.key_id.clone(), self.active_generation)
    }

    fn compute_mac(&self, key: &HeadMacKeyRefV2, message: &[u8]) -> Result<HeadMacTagV2> {
        if key.key_id() != self.key_id {
            return Err(SecureStoreError::KeyUnavailable);
        }
        let bytes = self
            .keys
            .get(&key.generation())
            .ok_or(SecureStoreError::KeyUnavailable)?;
        Ok(HeadMacTagV2::from_bytes(
            *blake3::keyed_hash(bytes, message).as_bytes(),
        ))
    }
}

/// Test-only keyed-BLAKE3 receipt authority; not a production signature scheme.
pub struct InMemoryReceiptAuthorityV2 {
    key_id: String,
    generation: u64,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for InMemoryReceiptAuthorityV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InMemoryReceiptAuthorityV2")
            .field("key_id", &self.key_id)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl InMemoryReceiptAuthorityV2 {
    /// Creates a random test-only receipt authority.
    pub fn random(key_id: impl Into<String>, generation: u64) -> Result<Self> {
        let key_id = key_id.into();
        ReceiptSigningKeyRefV2::new(key_id.clone(), generation)?;
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|_| SecureStoreError::CryptographicFailure)?;
        Ok(Self {
            key_id,
            generation,
            key,
        })
    }
}

impl DeletionReceiptSignerV2 for InMemoryReceiptAuthorityV2 {
    fn active_signing_key(&self) -> Result<ReceiptSigningKeyRefV2> {
        ReceiptSigningKeyRefV2::new(self.key_id.clone(), self.generation)
    }

    fn sign(&self, key: &ReceiptSigningKeyRefV2, message: &[u8]) -> Result<Vec<u8>> {
        if key.key_id() != self.key_id || key.generation() != self.generation {
            return Err(SecureStoreError::KeyUnavailable);
        }
        Ok(blake3::keyed_hash(&self.key, message).as_bytes().to_vec())
    }
}

impl DeletionReceiptVerifierV2 for InMemoryReceiptAuthorityV2 {
    fn verify(&self, key: &ReceiptSigningKeyRefV2, message: &[u8], signature: &[u8]) -> Result<()> {
        if key.key_id() != self.key_id
            || key.generation() != self.generation
            || signature.len() != 32
        {
            return Err(SecureStoreError::CryptographicFailure);
        }
        let expected = blake3::keyed_hash(&self.key, message);
        let actual: [u8; 32] = signature
            .try_into()
            .map_err(|_| SecureStoreError::CryptographicFailure)?;
        if expected != blake3::Hash::from_bytes(actual) {
            return Err(SecureStoreError::CryptographicFailure);
        }
        Ok(())
    }
}

/// Evidence verifier accepting structurally valid opaque handles in unit tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcceptAllDeletionEvidenceV2;

impl DeletionEvidenceVerifierV2 for AcceptAllDeletionEvidenceV2 {
    fn verify_absent_class(
        &self,
        _namespace: &StateNamespaceV2,
        _class: DeletionClosureClassV2,
        _evidence: &EvidenceHandleV2,
    ) -> Result<()> {
        Ok(())
    }

    fn verify_target(
        &self,
        _namespace: &StateNamespaceV2,
        _deletion: &DeletionHandleV2,
        _target: &DeletionTargetHandleV2,
        class: DeletionClosureClassV2,
        disposition: &DeletionTargetDispositionV2,
    ) -> Result<()> {
        disposition.validate_for_class(class)
    }
}

impl SuppressionCommitmentVerifierV2 for AcceptAllDeletionEvidenceV2 {
    fn verify_suppression(
        &self,
        _namespace: &StateNamespaceV2,
        _deletion: &DeletionHandleV2,
        _suppression_pending_workflow_root: &StateRootV2,
        _closure_root: &StateRootV2,
        _suppression_commitment: &StateRootV2,
    ) -> Result<()> {
        Ok(())
    }
}
