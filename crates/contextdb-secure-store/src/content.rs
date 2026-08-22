use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    ContentHandleV2, ContentSecurityContextV2, DekScopeV2, ErasureDomainV2, KeyAuthorityV2,
    KeyDescriptorV2, KeyLifecycleV2, Result, SECURE_STORE_FORMAT_VERSION, SealedPayloadV2,
    SecureStoreError, canonical_json,
};

/// Maximum plaintext accepted by one secure-store v2 content envelope.
pub const MAX_ENCRYPTED_CONTENT_BYTES: usize = 16 * 1024 * 1024;

/// Public authenticated header for an encrypted content object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "EncryptedContentHeaderWireV2",
    into = "EncryptedContentHeaderWireV2"
)]
pub struct EncryptedContentHeaderV2 {
    format_version: u16,
    content_handle: ContentHandleV2,
    key: KeyDescriptorV2,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedContentHeaderWireV2 {
    format_version: u16,
    content_handle: ContentHandleV2,
    key: KeyDescriptorV2,
}

impl TryFrom<EncryptedContentHeaderWireV2> for EncryptedContentHeaderV2 {
    type Error = SecureStoreError;

    fn try_from(value: EncryptedContentHeaderWireV2) -> Result<Self> {
        let header = Self {
            format_version: value.format_version,
            content_handle: value.content_handle,
            key: value.key,
        };
        header.validate()?;
        Ok(header)
    }
}

impl From<EncryptedContentHeaderV2> for EncryptedContentHeaderWireV2 {
    fn from(value: EncryptedContentHeaderV2) -> Self {
        Self {
            format_version: value.format_version,
            content_handle: value.content_handle,
            key: value.key,
        }
    }
}

impl EncryptedContentHeaderV2 {
    /// Returns the envelope format version.
    #[must_use]
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }

    /// Returns the opaque encrypted-object handle.
    #[must_use]
    pub fn content_handle(&self) -> &ContentHandleV2 {
        &self.content_handle
    }

    /// Returns the non-secret authority-managed key descriptor.
    #[must_use]
    pub fn key(&self) -> &KeyDescriptorV2 {
        &self.key
    }

    fn validate(&self) -> Result<()> {
        self.key.validate()?;
        if self.format_version != SECURE_STORE_FORMAT_VERSION
            || self.key.scope().content_handle() != &self.content_handle
        {
            return Err(SecureStoreError::Integrity(
                "encrypted content header is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Authenticated ciphertext envelope with no plaintext or plaintext digest.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "EncryptedContentWireV2", into = "EncryptedContentWireV2")]
pub struct EncryptedContentV2 {
    header: EncryptedContentHeaderV2,
    sealed: SealedPayloadV2,
}

impl EncryptedContentV2 {
    /// Creates and encrypts one object under a fresh random, per-object DEK.
    pub fn encrypt_new(
        authority: &mut dyn KeyAuthorityV2,
        erasure_domain: ErasureDomainV2,
        security_context: ContentSecurityContextV2,
        plaintext: &[u8],
    ) -> Result<Self> {
        Self::encrypt_preallocated(
            authority,
            ContentHandleV2::generate()?,
            erasure_domain,
            security_context,
            plaintext,
        )
    }

    /// Creates and encrypts one object under a caller-preallocated content
    /// handle and a fresh random DEK.
    ///
    /// Durable creation protocols persist the handle and exact DEK scope before
    /// crossing an external key-authority boundary. Retrying with the same
    /// scope therefore cannot silently allocate a second logical object.
    pub fn encrypt_preallocated(
        authority: &mut dyn KeyAuthorityV2,
        content_handle: ContentHandleV2,
        erasure_domain: ErasureDomainV2,
        security_context: ContentSecurityContextV2,
        plaintext: &[u8],
    ) -> Result<Self> {
        if plaintext.is_empty() || plaintext.len() > MAX_ENCRYPTED_CONTENT_BYTES {
            return Err(SecureStoreError::InvalidInput(
                "encrypted content size is outside the supported range".to_owned(),
            ));
        }
        let scope = DekScopeV2::new(content_handle.clone(), erasure_domain, security_context)?;
        let key = authority.create_random_dek(scope.clone())?;
        key.validate()?;
        if key.lifecycle() != KeyLifecycleV2::Active
            || key.generation() != 1
            || key.scope() != &scope
        {
            return Err(SecureStoreError::Integrity(
                "key authority returned an invalid fresh DEK descriptor".to_owned(),
            ));
        }
        Self::seal_existing(authority, key, plaintext)
    }

    /// Seals bounded plaintext under an already-created active descriptor.
    ///
    /// This is the local AEAD half of a crash-recoverable create protocol. The
    /// descriptor remains opaque key metadata; key bytes never cross this API.
    /// The authority is re-read before sealing so a stale or substituted
    /// descriptor is rejected.
    pub fn seal_existing(
        authority: &dyn KeyAuthorityV2,
        key: KeyDescriptorV2,
        plaintext: &[u8],
    ) -> Result<Self> {
        if plaintext.is_empty() || plaintext.len() > MAX_ENCRYPTED_CONTENT_BYTES {
            return Err(SecureStoreError::InvalidInput(
                "encrypted content size is outside the supported range".to_owned(),
            ));
        }
        key.validate()?;
        if key.lifecycle() != KeyLifecycleV2::Active || key.generation() != 1 {
            return Err(SecureStoreError::KeyUnavailable);
        }
        if authority.descriptor(key.key_handle())? != key {
            return Err(SecureStoreError::Integrity(
                "key authority descriptor changed before content sealing".to_owned(),
            ));
        }
        let content_handle = key.scope().content_handle().clone();
        let header = EncryptedContentHeaderV2 {
            format_version: SECURE_STORE_FORMAT_VERSION,
            content_handle,
            key,
        };
        let associated_data = associated_data(&header)?;
        let sealed = authority.seal(header.key(), plaintext, &associated_data)?;
        Self::try_from(EncryptedContentWireV2 { header, sealed })
    }

    /// Returns the public authenticated header.
    #[must_use]
    pub fn header(&self) -> &EncryptedContentHeaderV2 {
        &self.header
    }

    /// Returns the public nonce and ciphertext payload.
    #[must_use]
    pub fn sealed_payload(&self) -> &SealedPayloadV2 {
        &self.sealed
    }

    /// Decrypts through the authority without exposing DEK bytes.
    pub fn decrypt(
        &self,
        authority: &dyn KeyAuthorityV2,
        expected_context: &ContentSecurityContextV2,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        expected_context.validate()?;
        if self.header.key.scope().security_context() != expected_context {
            return Err(SecureStoreError::Integrity(
                "encrypted content security context does not match destination".to_owned(),
            ));
        }
        let current = authority.descriptor(self.header.key().key_handle())?;
        if current != *self.header.key() || current.lifecycle() != KeyLifecycleV2::Active {
            return Err(SecureStoreError::KeyUnavailable);
        }
        authority.open(&current, &self.sealed, &associated_data(&self.header)?)
    }

    fn validate(&self) -> Result<()> {
        self.header.validate()?;
        if self.sealed.ciphertext().len() > MAX_ENCRYPTED_CONTENT_BYTES + 16 {
            return Err(SecureStoreError::Integrity(
                "encrypted content exceeds the supported bound".to_owned(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for EncryptedContentV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedContentV2")
            .field("format_version", &self.header.format_version)
            .field("content_handle", &"[OPAQUE]")
            .field("key_handle", &"[OPAQUE]")
            .field("key_generation", &self.header.key.generation())
            .field("ciphertext_bytes", &self.sealed.ciphertext().len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EncryptedContentWireV2 {
    header: EncryptedContentHeaderV2,
    sealed: SealedPayloadV2,
}

impl TryFrom<EncryptedContentWireV2> for EncryptedContentV2 {
    type Error = SecureStoreError;

    fn try_from(value: EncryptedContentWireV2) -> Result<Self> {
        let envelope = Self {
            header: value.header,
            sealed: value.sealed,
        };
        envelope.validate()?;
        Ok(envelope)
    }
}

impl From<EncryptedContentV2> for EncryptedContentWireV2 {
    fn from(value: EncryptedContentV2) -> Self {
        Self {
            header: value.header,
            sealed: value.sealed,
        }
    }
}

fn associated_data(header: &EncryptedContentHeaderV2) -> Result<Vec<u8>> {
    let canonical_header = canonical_json(header)?;
    let mut bytes = Vec::with_capacity(40_usize.saturating_add(canonical_header.len()));
    bytes.extend_from_slice(b"contextdb/encrypted-content/v2\0");
    bytes.extend_from_slice(&(canonical_header.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&canonical_header);
    Ok(bytes)
}
