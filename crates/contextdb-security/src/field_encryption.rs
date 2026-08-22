use std::collections::BTreeSet;
use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{SecurityError, SecurityResult, canonical_json, require_label};

const RESTRICTED_FIELD_DOMAIN: &[u8] = b"contextdb/restricted-field/v1\0";

/// Maximum plaintext accepted by one application-level restricted-field
/// envelope. Larger content must use a separately bounded blob adapter.
pub const MAX_RESTRICTED_FIELD_BYTES: usize = 16 * 1024 * 1024;

/// Maximum number of exact scopes bound into one restricted field.
pub const MAX_RESTRICTED_FIELD_SCOPES: usize = 4_096;

/// Externally provisioned application-level field key. This role is distinct
/// from [`crate::BackupEncryptionKey`] so accidental cross-protocol reuse is
/// visible in host key management.
pub struct RestrictedFieldKey {
    key_id: String,
    rotation_generation: u64,
    bytes: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for RestrictedFieldKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestrictedFieldKey")
            .field("key_id", &self.key_id)
            .field("rotation_generation", &self.rotation_generation)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl RestrictedFieldKey {
    /// Imports a 256-bit key from an OS keyring, KMS, HSM, or host adapter.
    pub fn new(
        key_id: impl Into<String>,
        rotation_generation: u64,
        bytes: [u8; 32],
    ) -> SecurityResult<Self> {
        let key_id = key_id.into();
        require_label(&key_id, "restricted_field_key_id")?;
        if rotation_generation == 0 {
            return Err(SecurityError::InvalidInput(
                "restricted field key rotation generation must be non-zero".to_owned(),
            ));
        }
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(SecurityError::InvalidInput(
                "restricted field key cannot be all zero".to_owned(),
            ));
        }
        Ok(Self {
            key_id,
            rotation_generation,
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Generates a new key with the operating-system cryptographic RNG.
    pub fn generate(key_id: impl Into<String>, rotation_generation: u64) -> SecurityResult<Self> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SecurityError::CryptographicFailure)?;
        Self::new(key_id, rotation_generation, *bytes)
    }

    /// Stable non-secret key-management identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Monotonic key rotation generation.
    #[must_use]
    pub fn rotation_generation(&self) -> u64 {
        self.rotation_generation
    }
}

/// Canonical authorization context authenticated as AEAD associated data.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestrictedFieldMetadata {
    /// Logical database identity.
    pub database_id: String,
    /// Workspace/tenant identity.
    pub workspace_id: String,
    /// Canonical record or content identity.
    pub record_id: String,
    /// Stable field role, such as `observation.raw_content`.
    pub field_name: String,
    /// Exact scopes authorized at encryption time.
    pub scopes: BTreeSet<String>,
    /// Digest of the policy decision authorizing restricted persistence.
    pub policy_digest: String,
}

impl fmt::Debug for RestrictedFieldMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestrictedFieldMetadata")
            .field("database_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("record_id", &"[REDACTED]")
            .field("field_name", &self.field_name)
            .field("scope_count", &self.scopes.len())
            .field("policy_digest", &"[REDACTED]")
            .finish()
    }
}

/// Public authenticated header of one restricted-field envelope.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestrictedFieldHeader {
    /// Envelope format version.
    pub format_version: u16,
    /// Field-key identity.
    pub key_id: String,
    /// Field-key rotation generation.
    pub rotation_generation: u64,
    /// Exact associated authorization metadata.
    pub metadata: RestrictedFieldMetadata,
}

impl fmt::Debug for RestrictedFieldHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestrictedFieldHeader")
            .field("format_version", &self.format_version)
            .field("key_id", &self.key_id)
            .field("rotation_generation", &self.rotation_generation)
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Application-level encrypted restricted content.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedRestrictedField {
    /// Canonical authenticated header.
    pub header: RestrictedFieldHeader,
    /// Public 192-bit XChaCha nonce.
    pub nonce: Vec<u8>,
    /// Ciphertext including the Poly1305 authentication tag.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for EncryptedRestrictedField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedRestrictedField")
            .field("format_version", &self.header.format_version)
            .field("key_id", &self.header.key_id)
            .field("rotation_generation", &self.header.rotation_generation)
            .field("database_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("record_id", &"[REDACTED]")
            .field("field_name", &self.header.metadata.field_name)
            .field("scope_count", &self.header.metadata.scopes.len())
            .field("policy_digest", &"[REDACTED]")
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// Encrypts a bounded restricted field with metadata and key generation bound
/// into domain-separated associated data.
pub fn encrypt_restricted_field(
    plaintext: &[u8],
    metadata: RestrictedFieldMetadata,
    key: &RestrictedFieldKey,
) -> SecurityResult<EncryptedRestrictedField> {
    validate_metadata(&metadata)?;
    if plaintext.is_empty() || plaintext.len() > MAX_RESTRICTED_FIELD_BYTES {
        return Err(SecurityError::InvalidInput(
            "restricted field size is outside the supported range".to_owned(),
        ));
    }
    let header = RestrictedFieldHeader {
        format_version: 1,
        key_id: key.key_id.clone(),
        rotation_generation: key.rotation_generation,
        metadata,
    };
    let associated_data = associated_data(&header)?;
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| SecurityError::CryptographicFailure)?;
    let cipher_key = Key::from(*key.bytes);
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &associated_data,
            },
        )
        .map_err(|_| SecurityError::CryptographicFailure)?;
    Ok(EncryptedRestrictedField {
        header,
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Authorizes and decrypts one field. Expected metadata is checked before the
/// ciphertext is processed, preventing an envelope from being transplanted to
/// another workspace, record, field, policy, or scope set.
pub fn decrypt_restricted_field(
    envelope: &EncryptedRestrictedField,
    expected_metadata: &RestrictedFieldMetadata,
    key: &RestrictedFieldKey,
    raw_evidence_capability: bool,
) -> SecurityResult<Zeroizing<Vec<u8>>> {
    if !raw_evidence_capability {
        return Err(SecurityError::PolicyDenied(
            "restricted field read requires raw-evidence capability".to_owned(),
        ));
    }
    validate_envelope(envelope)?;
    validate_metadata(expected_metadata)?;
    if &envelope.header.metadata != expected_metadata
        || envelope.header.key_id != key.key_id
        || envelope.header.rotation_generation != key.rotation_generation
    {
        return Err(SecurityError::PolicyDenied(
            "restricted field metadata or key generation does not match authorization".to_owned(),
        ));
    }
    let nonce: [u8; 24] = envelope.nonce.as_slice().try_into().map_err(|_| {
        SecurityError::IntegrityFailure("invalid restricted nonce length".to_owned())
    })?;
    let associated_data = associated_data(&envelope.header)?;
    let cipher_key = Key::from(*key.bytes);
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let plaintext = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &associated_data,
            },
        )
        .map_err(|_| SecurityError::CryptographicFailure)?;
    Ok(Zeroizing::new(plaintext))
}

/// Re-encrypts a field under a strictly newer key generation. Plaintext is
/// zeroized after use and the associated authorization metadata is unchanged.
pub fn rewrap_restricted_field(
    envelope: &EncryptedRestrictedField,
    expected_metadata: &RestrictedFieldMetadata,
    old_key: &RestrictedFieldKey,
    new_key: &RestrictedFieldKey,
    raw_evidence_capability: bool,
) -> SecurityResult<EncryptedRestrictedField> {
    if new_key.rotation_generation <= old_key.rotation_generation
        || new_key.key_id == old_key.key_id
    {
        return Err(SecurityError::InvalidInput(
            "restricted field rewrap requires a distinct newer key generation".to_owned(),
        ));
    }
    let plaintext = decrypt_restricted_field(
        envelope,
        expected_metadata,
        old_key,
        raw_evidence_capability,
    )?;
    encrypt_restricted_field(&plaintext, expected_metadata.clone(), new_key)
}

fn validate_envelope(envelope: &EncryptedRestrictedField) -> SecurityResult<()> {
    validate_metadata(&envelope.header.metadata)?;
    require_label(&envelope.header.key_id, "restricted_field_key_id")?;
    if envelope.header.format_version != 1 || envelope.header.rotation_generation == 0 {
        return Err(SecurityError::IntegrityFailure(
            "restricted field header is invalid".to_owned(),
        ));
    }
    if envelope.nonce.len() != 24 {
        return Err(SecurityError::IntegrityFailure(
            "restricted field nonce is invalid".to_owned(),
        ));
    }
    let maximum_ciphertext = MAX_RESTRICTED_FIELD_BYTES.checked_add(16).ok_or_else(|| {
        SecurityError::ResourceExhausted("restricted ciphertext bound overflow".to_owned())
    })?;
    if envelope.ciphertext.len() <= 16 || envelope.ciphertext.len() > maximum_ciphertext {
        return Err(SecurityError::IntegrityFailure(
            "restricted field ciphertext size is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_metadata(metadata: &RestrictedFieldMetadata) -> SecurityResult<()> {
    require_label(&metadata.database_id, "restricted.database_id")?;
    require_label(&metadata.workspace_id, "restricted.workspace_id")?;
    require_label(&metadata.record_id, "restricted.record_id")?;
    require_label(&metadata.field_name, "restricted.field_name")?;
    require_digest(&metadata.policy_digest, "restricted.policy_digest")?;
    if metadata.scopes.is_empty() || metadata.scopes.len() > MAX_RESTRICTED_FIELD_SCOPES {
        return Err(SecurityError::PolicyDenied(
            "restricted field requires a bounded non-empty scope set".to_owned(),
        ));
    }
    for scope in &metadata.scopes {
        require_label(scope, "restricted.scope")?;
    }
    Ok(())
}

fn associated_data(header: &RestrictedFieldHeader) -> SecurityResult<Vec<u8>> {
    let header_bytes = canonical_json(header)?;
    let capacity = RESTRICTED_FIELD_DOMAIN
        .len()
        .checked_add(header_bytes.len())
        .ok_or_else(|| {
            SecurityError::ResourceExhausted("restricted associated-data overflow".to_owned())
        })?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(RESTRICTED_FIELD_DOMAIN);
    bytes.extend_from_slice(&header_bytes);
    Ok(bytes)
}

fn require_digest(value: &str, field: &str) -> SecurityResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SecurityError::InvalidInput(field.to_owned()));
    }
    Ok(())
}
