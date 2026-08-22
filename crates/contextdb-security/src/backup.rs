use std::collections::BTreeSet;
use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{SecurityError, SecurityResult, canonical_json, digest, require_label};

const BACKUP_SIGNATURE_DOMAIN: &[u8] = b"contextdb/backup-manifest/v1\0";

/// Maximum plaintext archive accepted by the reference envelope.
pub const MAX_BACKUP_BYTES: usize = 512 * 1024 * 1024;

/// Maximum number of independently named scopes in one encrypted archive.
pub const MAX_BACKUP_SCOPES: usize = 4_096;

/// Externally provisioned symmetric backup key. Key bytes are redacted from
/// `Debug` and zeroized on drop.
pub struct BackupEncryptionKey {
    key_id: String,
    generation: u64,
    bytes: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for BackupEncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupEncryptionKey")
            .field("key_id", &self.key_id)
            .field("generation", &self.generation)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl BackupEncryptionKey {
    /// Imports a 256-bit key supplied by an OS keyring, KMS, or HSM adapter.
    pub fn new(key_id: impl Into<String>, bytes: [u8; 32]) -> SecurityResult<Self> {
        Self::new_with_generation(key_id, 1, bytes)
    }

    /// Imports a versioned key supplied by an OS keyring, KMS, or HSM.
    pub fn new_with_generation(
        key_id: impl Into<String>,
        generation: u64,
        bytes: [u8; 32],
    ) -> SecurityResult<Self> {
        let key_id = key_id.into();
        require_label(&key_id, "encryption_key_id")?;
        if generation == 0 || bytes.iter().all(|byte| *byte == 0) {
            return Err(SecurityError::InvalidInput(
                "encryption key generation must be nonzero and key cannot be all zero".to_owned(),
            ));
        }
        Ok(Self {
            key_id,
            generation,
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Generates a key with the operating-system cryptographic RNG.
    pub fn generate(key_id: impl Into<String>) -> SecurityResult<Self> {
        Self::generate_with_generation(key_id, 1)
    }

    /// Generates a versioned key with the operating-system cryptographic RNG.
    pub fn generate_with_generation(
        key_id: impl Into<String>,
        generation: u64,
    ) -> SecurityResult<Self> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| SecurityError::CryptographicFailure)?;
        Self::new_with_generation(key_id, generation, bytes)
    }

    /// Stable non-secret key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Monotonic key-management generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// Externally provisioned Ed25519 key used to sign backup manifests.
pub struct BackupSigningKey {
    key_id: String,
    generation: u64,
    bytes: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for BackupSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupSigningKey")
            .field("key_id", &self.key_id)
            .field("generation", &self.generation)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl BackupSigningKey {
    /// Imports an Ed25519 signing seed supplied by a key-management adapter.
    pub fn new(key_id: impl Into<String>, bytes: [u8; 32]) -> SecurityResult<Self> {
        Self::new_with_generation(key_id, 1, bytes)
    }

    /// Imports a versioned Ed25519 seed from a key-management adapter.
    pub fn new_with_generation(
        key_id: impl Into<String>,
        generation: u64,
        bytes: [u8; 32],
    ) -> SecurityResult<Self> {
        let key_id = key_id.into();
        require_label(&key_id, "signing_key_id")?;
        if generation == 0 || bytes.iter().all(|byte| *byte == 0) {
            return Err(SecurityError::InvalidInput(
                "signing key generation must be nonzero and key cannot be all zero".to_owned(),
            ));
        }
        Ok(Self {
            key_id,
            generation,
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Generates a signing seed with the operating-system cryptographic RNG.
    pub fn generate(key_id: impl Into<String>) -> SecurityResult<Self> {
        Self::generate_with_generation(key_id, 1)
    }

    /// Generates a versioned signing seed with the operating-system RNG.
    pub fn generate_with_generation(
        key_id: impl Into<String>,
        generation: u64,
    ) -> SecurityResult<Self> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| SecurityError::CryptographicFailure)?;
        Self::new_with_generation(key_id, generation, bytes)
    }

    /// Exports the non-secret verification key.
    #[must_use]
    pub fn verifying_key(&self) -> BackupVerifyingKey {
        let key = SigningKey::from_bytes(&self.bytes);
        BackupVerifyingKey {
            key_id: self.key_id.clone(),
            generation: self.generation,
            bytes: key.verifying_key().to_bytes(),
        }
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn sign_domain(&self, domain: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut message = Vec::with_capacity(domain.len().saturating_add(payload.len()));
        message.extend_from_slice(domain);
        message.extend_from_slice(payload);
        SigningKey::from_bytes(&self.bytes)
            .sign(&message)
            .to_bytes()
            .to_vec()
    }
}

/// Public Ed25519 verification key for a signed backup manifest.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupVerifyingKey {
    /// Stable key-management identifier.
    pub key_id: String,
    /// Monotonic key-management generation.
    pub generation: u64,
    /// Raw Ed25519 public key bytes.
    pub bytes: [u8; 32],
}

impl fmt::Debug for BackupVerifyingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupVerifyingKey")
            .field("key_id", &self.key_id)
            .field("generation", &self.generation)
            .field("bytes", &"[PUBLIC KEY REDACTED]")
            .finish()
    }
}

impl BackupVerifyingKey {
    pub(crate) fn verify_domain(
        &self,
        domain: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> SecurityResult<()> {
        let signature_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| SecurityError::IntegrityFailure("invalid signature length".to_owned()))?;
        let signature = Signature::from_bytes(&signature_bytes);
        let key = VerifyingKey::from_bytes(&self.bytes)
            .map_err(|_| SecurityError::CryptographicFailure)?;
        let mut message = Vec::with_capacity(domain.len().saturating_add(payload.len()));
        message.extend_from_slice(domain);
        message.extend_from_slice(payload);
        key.verify_strict(&message, &signature)
            .map_err(|_| SecurityError::CryptographicFailure)
    }
}

/// Policy and lineage bound into encrypted backup associated data.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupHeader {
    /// Envelope format version.
    pub format_version: u16,
    /// Logical database identity.
    pub database_id: String,
    /// Exact workspace identity within the database.
    pub workspace_id: String,
    /// Exact exported scopes. Empty means no scope, not every scope.
    pub scopes: BTreeSet<String>,
    /// Digest of the policy decision authorizing export.
    pub policy_digest: String,
    /// Logical creation time supplied by the host.
    pub created_at_micros: i64,
    /// Mandatory expiry time.
    pub expires_at_micros: i64,
    /// Symmetric key identifier; key bytes are never embedded.
    pub encryption_key_id: String,
    /// Symmetric key-management generation.
    pub encryption_key_generation: u64,
    /// Manifest signing-key identifier.
    pub signing_key_id: String,
    /// Signing key-management generation.
    pub signing_key_generation: u64,
    /// Optional previous backup manifest digest for lineage.
    pub parent_manifest_digest: Option<String>,
}

impl fmt::Debug for BackupHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupHeader")
            .field("format_version", &self.format_version)
            .field("database_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("scope_count", &self.scopes.len())
            .field("policy_digest", &"[REDACTED]")
            .field("created_at_micros", &self.created_at_micros)
            .field("expires_at_micros", &self.expires_at_micros)
            .field("encryption_key_id", &self.encryption_key_id)
            .field("encryption_key_generation", &self.encryption_key_generation)
            .field("signing_key_id", &self.signing_key_id)
            .field("signing_key_generation", &self.signing_key_generation)
            .field(
                "has_parent_manifest",
                &self.parent_manifest_digest.is_some(),
            )
            .finish_non_exhaustive()
    }
}

/// Signed, content-free manifest for one encrypted backup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    /// Digest of the canonical associated-data header.
    pub header_digest: String,
    /// Digest of the complete authenticated ciphertext.
    pub ciphertext_digest: String,
    /// XChaCha20 nonce. It is public and unique for a key.
    pub nonce: Vec<u8>,
    /// Ed25519 signature over the canonical manifest payload.
    pub signature: Vec<u8>,
    /// Digest of the canonical signed payload, useful for lineage/audit.
    pub manifest_digest: String,
}

/// Portable encrypted backup envelope.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedBackup {
    /// Authenticated policy and lineage header.
    pub header: BackupHeader,
    /// Signed manifest.
    pub manifest: BackupManifest,
    /// XChaCha20-Poly1305 ciphertext including its authentication tag.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for EncryptedBackup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedBackup")
            .field("format_version", &self.header.format_version)
            .field("database_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("scope_count", &self.header.scopes.len())
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// Input used to produce an encrypted backup.
#[derive(Clone, Eq, PartialEq)]
pub struct BackupRequest<'a> {
    /// Canonical logical archive bytes.
    pub archive: &'a [u8],
    /// Logical database identity.
    pub database_id: &'a str,
    /// Exact workspace exported by this envelope.
    pub workspace_id: &'a str,
    /// Exact export scopes.
    pub scopes: BTreeSet<String>,
    /// Digest of the authorizing policy decision.
    pub policy_digest: &'a str,
    /// Logical creation time.
    pub created_at_micros: i64,
    /// Mandatory expiry time.
    pub expires_at_micros: i64,
    /// Previous backup manifest, when this backup extends a lineage.
    pub parent_manifest_digest: Option<String>,
}

impl fmt::Debug for BackupRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupRequest")
            .field("archive_bytes", &self.archive.len())
            .field("database_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("scope_count", &self.scopes.len())
            .field("policy_digest", &"[REDACTED]")
            .field("created_at_micros", &self.created_at_micros)
            .field("expires_at_micros", &self.expires_at_micros)
            .field(
                "has_parent_manifest",
                &self.parent_manifest_digest.is_some(),
            )
            .finish_non_exhaustive()
    }
}

/// Independent restore authorization evaluated before decryption.
#[derive(Clone, Eq, PartialEq)]
pub struct RestoreAuthorization {
    /// Current logical time.
    pub now_micros: i64,
    /// Expected logical database identity.
    pub expected_database_id: String,
    /// Expected workspace identity.
    pub expected_workspace_id: String,
    /// Exact archive policy digest permitted by the current restore decision.
    pub expected_policy_digest: String,
    /// Exact backup selected by a trusted inventory or audit record.
    pub expected_manifest_digest: String,
    /// Lowest encryption-key generation allowed by current policy.
    pub minimum_encryption_key_generation: u64,
    /// Lowest signing-key generation allowed by current policy.
    pub minimum_signing_key_generation: u64,
    /// Scopes the restore target is authorized to receive.
    pub allowed_scopes: BTreeSet<String>,
    /// Explicit restore capability. This cannot be inferred from file access.
    pub restore_capability: bool,
}

impl fmt::Debug for RestoreAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestoreAuthorization")
            .field("now_micros", &self.now_micros)
            .field("expected_database_id", &"[REDACTED]")
            .field("expected_workspace_id", &"[REDACTED]")
            .field("expected_policy_digest", &"[REDACTED]")
            .field("expected_manifest_digest", &"[REDACTED]")
            .field(
                "minimum_encryption_key_generation",
                &self.minimum_encryption_key_generation,
            )
            .field(
                "minimum_signing_key_generation",
                &self.minimum_signing_key_generation,
            )
            .field("allowed_scope_count", &self.allowed_scopes.len())
            .field("restore_capability", &self.restore_capability)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct SignedManifest<'a> {
    header_digest: &'a str,
    ciphertext_digest: &'a str,
    nonce: &'a [u8],
}

/// Encrypts an archive with XChaCha20-Poly1305 and signs its content-free
/// manifest with Ed25519.
pub fn encrypt_backup(
    request: &BackupRequest<'_>,
    encryption_key: &BackupEncryptionKey,
    signing_key: &BackupSigningKey,
) -> SecurityResult<EncryptedBackup> {
    validate_request(request)?;
    let header = BackupHeader {
        format_version: 1,
        database_id: request.database_id.to_owned(),
        workspace_id: request.workspace_id.to_owned(),
        scopes: request.scopes.clone(),
        policy_digest: request.policy_digest.to_owned(),
        created_at_micros: request.created_at_micros,
        expires_at_micros: request.expires_at_micros,
        encryption_key_id: encryption_key.key_id.clone(),
        encryption_key_generation: encryption_key.generation,
        signing_key_id: signing_key.key_id.clone(),
        signing_key_generation: signing_key.generation,
        parent_manifest_digest: request.parent_manifest_digest.clone(),
    };
    let associated_data = canonical_json(&header)?;
    let header_digest = digest(&associated_data);
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| SecurityError::CryptographicFailure)?;
    let cipher_key = Key::from(*encryption_key.bytes);
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let nonce_array = XNonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce_array,
            Payload {
                msg: request.archive,
                aad: &associated_data,
            },
        )
        .map_err(|_| SecurityError::CryptographicFailure)?;
    let ciphertext_digest = digest(&ciphertext);
    let signed = SignedManifest {
        header_digest: &header_digest,
        ciphertext_digest: &ciphertext_digest,
        nonce: &nonce,
    };
    let signed_bytes = canonical_json(&signed)?;
    let manifest_digest = digest(&signed_bytes);
    let signature = signing_key.sign_domain(BACKUP_SIGNATURE_DOMAIN, &signed_bytes);
    Ok(EncryptedBackup {
        header,
        manifest: BackupManifest {
            header_digest,
            ciphertext_digest,
            nonce: nonce.to_vec(),
            signature,
            manifest_digest,
        },
        ciphertext,
    })
}

/// Verifies policy, signature, ciphertext, and plaintext digest before
/// returning canonical archive bytes.
pub fn restore_backup(
    backup: &EncryptedBackup,
    encryption_key: &BackupEncryptionKey,
    verifying_key: &BackupVerifyingKey,
    authorization: &RestoreAuthorization,
) -> SecurityResult<Zeroizing<Vec<u8>>> {
    validate_restore_policy(backup, encryption_key, verifying_key, authorization)?;
    verify_backup_envelope(backup, verifying_key)?;
    let associated_data = canonical_json(&backup.header)?;
    let nonce: [u8; 24] = backup
        .manifest
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| SecurityError::IntegrityFailure("invalid nonce length".to_owned()))?;
    let cipher_key = Key::from(*encryption_key.bytes);
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let nonce_array = XNonce::from(nonce);
    let plaintext = cipher
        .decrypt(
            &nonce_array,
            Payload {
                msg: &backup.ciphertext,
                aad: &associated_data,
            },
        )
        .map_err(|_| SecurityError::CryptographicFailure)?;
    Ok(Zeroizing::new(plaintext))
}

/// Verifies the bounded canonical header, ciphertext digest, nonce, manifest
/// digest, key identity, and domain-separated signature without decrypting the
/// archive.
pub fn verify_backup_envelope(
    backup: &EncryptedBackup,
    verifying_key: &BackupVerifyingKey,
) -> SecurityResult<()> {
    validate_header(&backup.header)?;
    if backup.header.signing_key_id != verifying_key.key_id {
        return Err(SecurityError::IntegrityFailure(
            "backup signing-key identity mismatch".to_owned(),
        ));
    }
    if backup.header.signing_key_generation != verifying_key.generation {
        return Err(SecurityError::IntegrityFailure(
            "backup signing-key generation mismatch".to_owned(),
        ));
    }
    if backup.ciphertext.len() > MAX_BACKUP_BYTES.saturating_add(64) {
        return Err(SecurityError::ResourceExhausted(
            "encrypted backup exceeds the supported bound".to_owned(),
        ));
    }
    let associated_data = canonical_json(&backup.header)?;
    if digest(&associated_data) != backup.manifest.header_digest
        || digest(&backup.ciphertext) != backup.manifest.ciphertext_digest
    {
        return Err(SecurityError::IntegrityFailure(
            "backup header or ciphertext digest mismatch".to_owned(),
        ));
    }
    let nonce: [u8; 24] = backup
        .manifest
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| SecurityError::IntegrityFailure("invalid nonce length".to_owned()))?;
    let signed = SignedManifest {
        header_digest: &backup.manifest.header_digest,
        ciphertext_digest: &backup.manifest.ciphertext_digest,
        nonce: &nonce,
    };
    let signed_bytes = canonical_json(&signed)?;
    if digest(&signed_bytes) != backup.manifest.manifest_digest {
        return Err(SecurityError::IntegrityFailure(
            "manifest digest mismatch".to_owned(),
        ));
    }
    verifying_key.verify_domain(
        BACKUP_SIGNATURE_DOMAIN,
        &signed_bytes,
        &backup.manifest.signature,
    )
}

/// Verifies two independently signed envelopes and proves that `child` is the
/// next selected backup in the same database lineage. Signing keys may rotate.
pub fn verify_backup_successor(
    parent: &EncryptedBackup,
    parent_verifying_key: &BackupVerifyingKey,
    child: &EncryptedBackup,
    child_verifying_key: &BackupVerifyingKey,
) -> SecurityResult<()> {
    verify_backup_envelope(parent, parent_verifying_key)?;
    verify_backup_envelope(child, child_verifying_key)?;
    if child.header.database_id != parent.header.database_id
        || child.header.workspace_id != parent.header.workspace_id
        || child.header.parent_manifest_digest.as_deref()
            != Some(parent.manifest.manifest_digest.as_str())
        || child.header.created_at_micros <= parent.header.created_at_micros
        || child.header.encryption_key_generation < parent.header.encryption_key_generation
        || child.header.signing_key_generation < parent.header.signing_key_generation
        || child.manifest.manifest_digest == parent.manifest.manifest_digest
    {
        return Err(SecurityError::IntegrityFailure(
            "backup lineage successor binding is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_request(request: &BackupRequest<'_>) -> SecurityResult<()> {
    require_label(request.database_id, "database_id")?;
    require_label(request.workspace_id, "workspace_id")?;
    require_digest(request.policy_digest, "policy_digest")?;
    if request.archive.is_empty() || request.archive.len() > MAX_BACKUP_BYTES {
        return Err(SecurityError::InvalidInput(
            "archive size is outside the supported range".to_owned(),
        ));
    }
    if request.scopes.is_empty() {
        return Err(SecurityError::PolicyDenied(
            "an encrypted export requires explicit non-empty scopes".to_owned(),
        ));
    }
    if request.scopes.len() > MAX_BACKUP_SCOPES {
        return Err(SecurityError::ResourceExhausted(
            "encrypted export has too many scopes".to_owned(),
        ));
    }
    for scope in &request.scopes {
        require_label(scope, "scope")?;
    }
    if request.expires_at_micros <= request.created_at_micros {
        return Err(SecurityError::InvalidInput(
            "backup expiry must follow creation".to_owned(),
        ));
    }
    if let Some(parent) = &request.parent_manifest_digest {
        require_digest(parent, "parent_manifest_digest")?;
    }
    Ok(())
}

fn validate_restore_policy(
    backup: &EncryptedBackup,
    encryption_key: &BackupEncryptionKey,
    verifying_key: &BackupVerifyingKey,
    authorization: &RestoreAuthorization,
) -> SecurityResult<()> {
    if !authorization.restore_capability {
        return Err(SecurityError::PolicyDenied(
            "explicit restore capability is required".to_owned(),
        ));
    }
    require_label(&authorization.expected_database_id, "expected_database_id")?;
    require_label(
        &authorization.expected_workspace_id,
        "expected_workspace_id",
    )?;
    require_digest(
        &authorization.expected_policy_digest,
        "expected_policy_digest",
    )?;
    require_digest(
        &authorization.expected_manifest_digest,
        "expected_manifest_digest",
    )?;
    if authorization.allowed_scopes.len() > MAX_BACKUP_SCOPES {
        return Err(SecurityError::ResourceExhausted(
            "restore authorization has too many scopes".to_owned(),
        ));
    }
    for scope in &authorization.allowed_scopes {
        require_label(scope, "allowed_scope")?;
    }
    validate_header(&backup.header)?;
    if backup.header.format_version != 1
        || backup.header.database_id != authorization.expected_database_id
        || backup.header.workspace_id != authorization.expected_workspace_id
        || backup.header.policy_digest != authorization.expected_policy_digest
        || backup.manifest.manifest_digest != authorization.expected_manifest_digest
        || backup.header.encryption_key_id != encryption_key.key_id
        || backup.header.encryption_key_generation != encryption_key.generation
        || backup.header.encryption_key_generation < authorization.minimum_encryption_key_generation
        || backup.header.signing_key_id != verifying_key.key_id
        || backup.header.signing_key_generation != verifying_key.generation
        || backup.header.signing_key_generation < authorization.minimum_signing_key_generation
    {
        return Err(SecurityError::PolicyDenied(
            "backup identity or key binding does not match restore target".to_owned(),
        ));
    }
    if authorization.now_micros < backup.header.created_at_micros {
        return Err(SecurityError::PolicyDenied(
            "backup is not valid yet".to_owned(),
        ));
    }
    if authorization.now_micros >= backup.header.expires_at_micros {
        return Err(SecurityError::PolicyDenied("backup is expired".to_owned()));
    }
    if !backup
        .header
        .scopes
        .is_subset(&authorization.allowed_scopes)
    {
        return Err(SecurityError::PolicyDenied(
            "restore target does not authorize every exported scope".to_owned(),
        ));
    }
    if backup.ciphertext.len() > MAX_BACKUP_BYTES.saturating_add(64) {
        return Err(SecurityError::ResourceExhausted(
            "encrypted backup exceeds the supported bound".to_owned(),
        ));
    }
    Ok(())
}

fn validate_header(header: &BackupHeader) -> SecurityResult<()> {
    if header.format_version != 1 {
        return Err(SecurityError::IntegrityFailure(
            "unsupported backup format version".to_owned(),
        ));
    }
    require_label(&header.database_id, "database_id")?;
    require_label(&header.workspace_id, "workspace_id")?;
    require_digest(&header.policy_digest, "policy_digest")?;
    require_label(&header.encryption_key_id, "encryption_key_id")?;
    require_label(&header.signing_key_id, "signing_key_id")?;
    if header.encryption_key_generation == 0 || header.signing_key_generation == 0 {
        return Err(SecurityError::InvalidInput(
            "backup key generations must be nonzero".to_owned(),
        ));
    }
    if header.scopes.is_empty() || header.scopes.len() > MAX_BACKUP_SCOPES {
        return Err(SecurityError::IntegrityFailure(
            "backup scope set is outside the supported bound".to_owned(),
        ));
    }
    for scope in &header.scopes {
        require_label(scope, "scope")?;
    }
    if header.expires_at_micros <= header.created_at_micros {
        return Err(SecurityError::IntegrityFailure(
            "backup expiry is invalid".to_owned(),
        ));
    }
    if let Some(parent) = &header.parent_manifest_digest {
        require_digest(parent, "parent_manifest_digest")?;
    }
    Ok(())
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
