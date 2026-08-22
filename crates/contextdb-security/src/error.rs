use thiserror::Error;

/// Fail-closed security-kernel error.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SecurityError {
    /// A required identifier, scope, or policy field was absent or malformed.
    #[error("invalid security input: {0}")]
    InvalidInput(String),
    /// The caller lacks the explicit capability required for the operation.
    #[error("security policy denied the operation: {0}")]
    PolicyDenied(String),
    /// Secret policy rejected content before persistence or disclosure.
    #[error("secret policy rejected content")]
    SecretRejected,
    /// A quota or concurrency admission limit was exhausted.
    #[error("resource quota exhausted: {0}")]
    ResourceExhausted(String),
    /// Cryptographic encryption, decryption, signing, or verification failed.
    #[error("cryptographic verification failed")]
    CryptographicFailure,
    /// A digest, signature, chain link, or canonical envelope was corrupted.
    #[error("integrity verification failed: {0}")]
    IntegrityFailure(String),
    /// A deletion cannot be declared complete while required targets remain.
    #[error("deletion is incomplete: {0}")]
    DeletionIncomplete(String),
    /// Canonical serialization failed.
    #[error("canonical serialization failed")]
    Serialization,
}

/// Security-kernel result alias.
pub type SecurityResult<T> = Result<T, SecurityError>;

pub(crate) fn require_label(value: &str, field: &str) -> SecurityResult<()> {
    if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(SecurityError::InvalidInput(field.to_owned()));
    }
    Ok(())
}

pub(crate) fn canonical_json<T: serde::Serialize + ?Sized>(value: &T) -> SecurityResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| SecurityError::Serialization)
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
