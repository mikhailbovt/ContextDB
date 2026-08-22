use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    EncryptedRestrictedField, RestrictedFieldKey, RestrictedFieldMetadata, SecurityError,
    SecurityResult, encrypt_restricted_field, require_label,
};

/// Maximum number of secret findings retained for one bounded input.
pub const MAX_SECRET_FINDINGS: usize = 1_024;

const SECRET_DIGEST_DOMAIN: &[u8] = b"contextdb/secret-digest/v1\0";

/// Externally provisioned key for privacy-preserving `DigestOnly` output.
/// This role is distinct from backup and restricted-field encryption keys.
pub struct SecretDigestKey {
    key_id: String,
    generation: u64,
    bytes: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for SecretDigestKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretDigestKey")
            .field("key_id", &self.key_id)
            .field("generation", &self.generation)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl SecretDigestKey {
    /// Imports a nonzero 256-bit key and monotonic generation from a KMS or
    /// platform keyring.
    pub fn new(
        key_id: impl Into<String>,
        generation: u64,
        bytes: [u8; 32],
    ) -> SecurityResult<Self> {
        let key_id = key_id.into();
        require_label(&key_id, "secret_digest_key_id")?;
        if generation == 0 || bytes.iter().all(|byte| *byte == 0) {
            return Err(SecurityError::InvalidInput(
                "secret digest key generation and material must be nonzero".to_owned(),
            ));
        }
        Ok(Self {
            key_id,
            generation,
            bytes: Zeroizing::new(bytes),
        })
    }
}

/// Content-free secret classification.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretClass {
    /// Provider or service API key.
    ApiKey,
    /// Password assignment or password-bearing URL.
    Password,
    /// PEM or SSH private key material.
    PrivateKey,
    /// Bearer, OAuth, session, or personal access token.
    AccessToken,
    /// Database/service connection string carrying credentials.
    ConnectionString,
    /// Generic credential assignment.
    Credential,
    /// Long token with unusually high Shannon entropy.
    HighEntropy,
    /// Recognized vendor-specific secret format.
    KnownFormat,
}

/// One secret finding without the matched secret bytes.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretFinding {
    /// Secret class.
    pub class: SecretClass,
    /// UTF-8 byte start offset.
    pub start: usize,
    /// UTF-8 byte end offset, exclusive.
    pub end: usize,
}

impl fmt::Debug for SecretFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretFinding")
            .field("class", &self.class)
            .field("start", &self.start)
            .field("end", &self.end)
            .finish()
    }
}

/// Fail-closed action applied when at least one secret is found.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretAction {
    /// Reject before persistence.
    Reject,
    /// Replace exact spans before persistence.
    Redact,
    /// Persist only a digest of the complete input.
    DigestOnly,
    /// Persist an application-level AEAD envelope under a separately supplied
    /// restricted-field key and exact authorization metadata.
    EncryptedRestricted,
    /// Persist only a trusted source handle.
    SourceHandleOnly,
    /// Permit only an explicit `vault://` reference, never inline content.
    VaultReferenceOnly,
}

/// Secret-scanning policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPolicy {
    /// Action applied to matching content.
    pub action: SecretAction,
    /// Maximum UTF-8 bytes scanned before fail-closed refusal.
    pub max_scan_bytes: usize,
}

impl Default for SecretPolicy {
    fn default() -> Self {
        Self {
            action: SecretAction::Reject,
            max_scan_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum ProtectedContentKind {
    Clear(String),
    Redacted(String),
    DigestOnly {
        key_id: String,
        generation: u64,
        digest: String,
    },
    EncryptedRestricted(Box<EncryptedRestrictedField>),
    SourceHandle(String),
    VaultReference(String),
}

/// Safe content form returned only by the validated secret-policy constructors.
/// It is serialization-only: callers cannot construct or deserialize a forged
/// clear-secret verdict.
///
/// ```compile_fail
/// use contextdb_security::ProtectedContent;
///
/// let _: ProtectedContent = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProtectedContent(ProtectedContentKind);

/// Payload-free discriminator for a protected-content representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedContentKindName {
    /// Original content passed the configured scanner.
    Clear,
    /// Detected spans were replaced.
    Redacted,
    /// A keyed privacy digest is stored.
    DigestOnly,
    /// Field-level AEAD is stored.
    EncryptedRestricted,
    /// Only a trusted source handle is stored.
    SourceHandle,
    /// Only a strict opaque vault handle is stored.
    VaultReference,
}

impl ProtectedContent {
    /// Representation discriminator without protected bytes.
    #[must_use]
    pub fn kind(&self) -> ProtectedContentKindName {
        match self.0 {
            ProtectedContentKind::Clear(_) => ProtectedContentKindName::Clear,
            ProtectedContentKind::Redacted(_) => ProtectedContentKindName::Redacted,
            ProtectedContentKind::DigestOnly { .. } => ProtectedContentKindName::DigestOnly,
            ProtectedContentKind::EncryptedRestricted(_) => {
                ProtectedContentKindName::EncryptedRestricted
            }
            ProtectedContentKind::SourceHandle(_) => ProtectedContentKindName::SourceHandle,
            ProtectedContentKind::VaultReference(_) => ProtectedContentKindName::VaultReference,
        }
    }

    /// Clear or redacted text, when that representation is present.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        match &self.0 {
            ProtectedContentKind::Clear(value) | ProtectedContentKind::Redacted(value) => {
                Some(value)
            }
            _ => None,
        }
    }

    /// Keyed digest metadata, when `DigestOnly` was explicitly configured.
    #[must_use]
    pub fn keyed_digest(&self) -> Option<(&str, u64, &str)> {
        match &self.0 {
            ProtectedContentKind::DigestOnly {
                key_id,
                generation,
                digest,
            } => Some((key_id, *generation, digest)),
            _ => None,
        }
    }

    /// Restricted-field AEAD envelope, when present.
    #[must_use]
    pub fn encrypted_restricted(&self) -> Option<&EncryptedRestrictedField> {
        match &self.0 {
            ProtectedContentKind::EncryptedRestricted(value) => Some(value),
            _ => None,
        }
    }

    /// Trusted source or vault handle, when present.
    #[must_use]
    pub fn handle(&self) -> Option<&str> {
        match &self.0 {
            ProtectedContentKind::SourceHandle(value)
            | ProtectedContentKind::VaultReference(value) => Some(value),
            _ => None,
        }
    }
}

impl fmt::Debug for ProtectedContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, bytes) = match self {
            Self(ProtectedContentKind::Clear(value)) => ("clear", value.len()),
            Self(ProtectedContentKind::Redacted(value)) => ("redacted", value.len()),
            Self(ProtectedContentKind::DigestOnly { .. }) => ("digest_only", 0),
            Self(ProtectedContentKind::EncryptedRestricted(value)) => {
                ("encrypted_restricted", value.ciphertext.len())
            }
            Self(ProtectedContentKind::SourceHandle(_)) => ("source_handle", 0),
            Self(ProtectedContentKind::VaultReference(_)) => ("vault_reference", 0),
        };
        formatter
            .debug_struct("ProtectedContent")
            .field("kind", &kind)
            .field("bytes", &bytes)
            .finish_non_exhaustive()
    }
}

/// Scanner outcome safe to log or audit.
///
/// This is also serialization-only so wire input cannot assert that arbitrary
/// content was scanned or that restricted processing is unnecessary:
///
/// ```compile_fail
/// use contextdb_security::SecretPolicyOutcome;
///
/// let _: SecretPolicyOutcome = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPolicyOutcome {
    /// Safe persistence representation.
    protected: ProtectedContent,
    /// Content-free findings.
    findings: Vec<SecretFinding>,
    /// Whether embeddings/model calls/summaries are forbidden.
    restricted_processing: bool,
}

impl SecretPolicyOutcome {
    /// Validated safe persistence representation.
    #[must_use]
    pub fn protected(&self) -> &ProtectedContent {
        &self.protected
    }

    /// Consumes the outcome and returns its validated representation.
    #[must_use]
    pub fn into_protected(self) -> ProtectedContent {
        self.protected
    }

    /// Content-free scanner findings.
    #[must_use]
    pub fn findings(&self) -> &[SecretFinding] {
        &self.findings
    }

    /// Whether downstream embedding/model/summary processing is forbidden.
    #[must_use]
    pub fn restricted_processing(&self) -> bool {
        self.restricted_processing
    }
}

impl fmt::Debug for SecretPolicyOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretPolicyOutcome")
            .field("protected", &self.protected)
            .field("finding_count", &self.findings.len())
            .field("restricted_processing", &self.restricted_processing)
            .finish()
    }
}

/// Scans bounded UTF-8 content and returns only locations, classes, and
/// digests. Matched bytes are never copied into a finding.
pub fn scan_secrets(input: &str, max_scan_bytes: usize) -> SecurityResult<Vec<SecretFinding>> {
    if max_scan_bytes == 0 || input.len() > max_scan_bytes {
        return Err(SecurityError::ResourceExhausted(
            "secret scan byte budget exceeded".to_owned(),
        ));
    }
    let mut raw = Vec::<(SecretClass, usize, usize)>::new();
    scan_private_keys(input, &mut raw);
    scan_assignments(input, &mut raw);
    scan_tokens(input, &mut raw);
    scan_connection_strings(input, &mut raw);
    scan_high_entropy(input, &mut raw);
    raw.sort_unstable_by_key(|(class, start, end)| (*start, *end, *class));
    raw.dedup();
    if raw.len() > MAX_SECRET_FINDINGS {
        return Err(SecurityError::ResourceExhausted(
            "secret finding budget exceeded".to_owned(),
        ));
    }
    Ok(raw
        .into_iter()
        .map(|(class, start, end)| SecretFinding { class, start, end })
        .collect())
}

/// Applies secret policy before persistence, embedding, summarization, model
/// routing, or trace materialization.
pub fn apply_secret_policy(
    input: &str,
    policy: &SecretPolicy,
    trusted_source_handle: Option<&str>,
) -> SecurityResult<SecretPolicyOutcome> {
    apply_secret_policy_inner(input, policy, trusted_source_handle, None, None)
}

/// Applies secret policy with an external key for privacy-preserving
/// [`SecretAction::DigestOnly`]. Without this explicit key, DigestOnly fails
/// closed rather than exposing an offline dictionary verifier.
pub fn apply_secret_policy_with_digest_key(
    input: &str,
    policy: &SecretPolicy,
    trusted_source_handle: Option<&str>,
    digest_key: &SecretDigestKey,
) -> SecurityResult<SecretPolicyOutcome> {
    apply_secret_policy_inner(input, policy, trusted_source_handle, Some(digest_key), None)
}

/// Applies secret policy with an external restricted-field key and exact
/// authorization metadata available for [`SecretAction::EncryptedRestricted`].
pub fn apply_secret_policy_with_encryption(
    input: &str,
    policy: &SecretPolicy,
    trusted_source_handle: Option<&str>,
    key: &RestrictedFieldKey,
    metadata: RestrictedFieldMetadata,
) -> SecurityResult<SecretPolicyOutcome> {
    apply_secret_policy_inner(
        input,
        policy,
        trusted_source_handle,
        None,
        Some((key, metadata)),
    )
}

fn apply_secret_policy_inner(
    input: &str,
    policy: &SecretPolicy,
    trusted_source_handle: Option<&str>,
    digest_key: Option<&SecretDigestKey>,
    restricted_encryption: Option<(&RestrictedFieldKey, RestrictedFieldMetadata)>,
) -> SecurityResult<SecretPolicyOutcome> {
    let findings = scan_secrets(input, policy.max_scan_bytes)?;
    if policy.action == SecretAction::VaultReferenceOnly {
        if !findings.is_empty() || !is_vault_reference(input) {
            return Err(SecurityError::PolicyDenied(
                "vault-reference-only policy requires a secret-free opaque vault handle".to_owned(),
            ));
        }
        return Ok(SecretPolicyOutcome {
            protected: ProtectedContent(ProtectedContentKind::VaultReference(input.to_owned())),
            findings,
            restricted_processing: true,
        });
    }
    if policy.action == SecretAction::DigestOnly {
        let key = digest_key.ok_or_else(|| {
            SecurityError::PolicyDenied(
                "digest-only policy requires an external privacy-digest key".to_owned(),
            )
        })?;
        return Ok(SecretPolicyOutcome {
            protected: ProtectedContent(ProtectedContentKind::DigestOnly {
                key_id: key.key_id.clone(),
                generation: key.generation,
                digest: keyed_secret_digest(input.as_bytes(), key),
            }),
            findings,
            restricted_processing: true,
        });
    }
    if policy.action == SecretAction::SourceHandleOnly {
        let handle = trusted_source_handle.ok_or_else(|| {
            SecurityError::PolicyDenied(
                "source-handle-only policy requires a trusted handle".to_owned(),
            )
        })?;
        require_label(handle, "trusted_source_handle")?;
        return Ok(SecretPolicyOutcome {
            protected: ProtectedContent(ProtectedContentKind::SourceHandle(handle.to_owned())),
            findings,
            restricted_processing: true,
        });
    }
    if policy.action == SecretAction::EncryptedRestricted {
        let (key, metadata) = restricted_encryption.ok_or_else(|| {
            SecurityError::PolicyDenied(
                "encrypted-restricted policy requires an external field key and metadata"
                    .to_owned(),
            )
        })?;
        return Ok(SecretPolicyOutcome {
            protected: ProtectedContent(ProtectedContentKind::EncryptedRestricted(Box::new(
                encrypt_restricted_field(input.as_bytes(), metadata, key)?,
            ))),
            findings,
            restricted_processing: true,
        });
    }
    if findings.is_empty() {
        return Ok(SecretPolicyOutcome {
            protected: ProtectedContent(ProtectedContentKind::Clear(input.to_owned())),
            findings,
            restricted_processing: false,
        });
    }
    let protected = match policy.action {
        SecretAction::Reject => return Err(SecurityError::SecretRejected),
        SecretAction::Redact => {
            ProtectedContent(ProtectedContentKind::Redacted(redact(input, &findings)?))
        }
        SecretAction::DigestOnly
        | SecretAction::EncryptedRestricted
        | SecretAction::SourceHandleOnly
        | SecretAction::VaultReferenceOnly => {
            return Err(SecurityError::IntegrityFailure(
                "strict secret policy branch was not handled before finding action".to_owned(),
            ));
        }
    };
    Ok(SecretPolicyOutcome {
        protected,
        findings,
        restricted_processing: true,
    })
}

fn scan_private_keys(input: &str, findings: &mut Vec<(SecretClass, usize, usize)>) {
    let upper = input.to_ascii_uppercase();
    let mut offset = 0;
    while let Some(relative) = upper[offset..].find("-----BEGIN ") {
        let start = offset + relative;
        let line_end = upper[start..]
            .find("-----\n")
            .map_or(upper.len(), |value| start + value + 6);
        let header = &upper[start..line_end.min(upper.len())];
        if header.contains("PRIVATE KEY") || header.contains("OPENSSH PRIVATE") {
            let end = upper[start..]
                .find("-----END ")
                .and_then(|relative_end| {
                    let trailer_start = start + relative_end;
                    upper[trailer_start..].find("-----").and_then(|first| {
                        upper[trailer_start + first + 5..]
                            .find("-----")
                            .map(|last| trailer_start + first + 5 + last + 5)
                    })
                })
                .unwrap_or(line_end);
            findings.push((SecretClass::PrivateKey, start, end));
        }
        offset = line_end.max(start.saturating_add(1));
        if offset >= upper.len() {
            break;
        }
    }
}

fn scan_assignments(input: &str, findings: &mut Vec<(SecretClass, usize, usize)>) {
    let lower = input.to_ascii_lowercase();
    for (needle, class) in [
        ("password", SecretClass::Password),
        ("passwd", SecretClass::Password),
        ("api_key", SecretClass::ApiKey),
        ("apikey", SecretClass::ApiKey),
        ("access_token", SecretClass::AccessToken),
        ("client_secret", SecretClass::Credential),
        ("secret", SecretClass::Credential),
    ] {
        let mut offset = 0;
        while let Some(relative) = lower[offset..].find(needle) {
            let name_start = offset + relative;
            let after_name = name_start + needle.len();
            let tail = &input.as_bytes()[after_name..];
            let Some(separator_relative) =
                tail.iter().position(|byte| matches!(*byte, b'=' | b':'))
            else {
                break;
            };
            if separator_relative > 4 {
                offset = after_name;
                continue;
            }
            let mut start = after_name + separator_relative + 1;
            while input
                .as_bytes()
                .get(start)
                .is_some_and(u8::is_ascii_whitespace)
            {
                start += 1;
            }
            let quote = input.as_bytes().get(start).copied();
            if matches!(quote, Some(b'\'' | b'"')) {
                start += 1;
            }
            let end = scan_token_end(input.as_bytes(), start, quote);
            if end.saturating_sub(start) >= 6 {
                findings.push((class, start, end));
            }
            offset = end.max(after_name);
            if offset >= input.len() {
                break;
            }
        }
    }
}

fn scan_tokens(input: &str, findings: &mut Vec<(SecretClass, usize, usize)>) {
    let bytes = input.as_bytes();
    for (prefix, minimum, class) in [
        ("AKIA", 20, SecretClass::KnownFormat),
        ("ASIA", 20, SecretClass::KnownFormat),
        ("ghp_", 24, SecretClass::AccessToken),
        ("github_pat_", 32, SecretClass::AccessToken),
        ("sk-", 24, SecretClass::ApiKey),
        ("Bearer ", 20, SecretClass::AccessToken),
    ] {
        let mut offset = 0;
        while let Some(relative) = input[offset..].find(prefix) {
            let start = offset + relative + usize::from(prefix == "Bearer ") * prefix.len();
            let end = bytes[start..]
                .iter()
                .position(|byte| !is_token_byte(*byte))
                .map_or(bytes.len(), |relative_end| start + relative_end);
            if end.saturating_sub(start) >= minimum {
                findings.push((class, start, end));
            }
            offset = end.max(offset.saturating_add(relative).saturating_add(1));
            if offset >= input.len() {
                break;
            }
        }
    }
    for (start, end) in ascii_tokens(bytes, 24) {
        let token = &input[start..end];
        if token.matches('.').count() == 2
            && token
                .split('.')
                .all(|part| part.len() >= 6 && part.bytes().all(is_token_byte))
        {
            findings.push((SecretClass::AccessToken, start, end));
        }
    }
}

fn scan_connection_strings(input: &str, findings: &mut Vec<(SecretClass, usize, usize)>) {
    let bytes = input.as_bytes();
    let mut offset = 0;
    while let Some(relative) = input[offset..].find("://") {
        let scheme_end = offset + relative + 3;
        let end = bytes[scheme_end..]
            .iter()
            .position(u8::is_ascii_whitespace)
            .map_or(bytes.len(), |relative_end| scheme_end + relative_end);
        let candidate = &input[scheme_end..end];
        if let Some(at) = candidate.find('@') {
            let authority = &candidate[..at];
            if authority.contains(':') {
                findings.push((SecretClass::ConnectionString, scheme_end, scheme_end + at));
            }
        }
        offset = end.max(scheme_end);
        if offset >= input.len() {
            break;
        }
    }
}

fn scan_high_entropy(input: &str, findings: &mut Vec<(SecretClass, usize, usize)>) {
    for (start, end) in ascii_tokens(input.as_bytes(), 32) {
        let token = &input.as_bytes()[start..end];
        if shannon_entropy(token) >= 4.3 {
            findings.push((SecretClass::HighEntropy, start, end));
        }
    }
}

fn ascii_tokens(bytes: &[u8], minimum: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = None;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if is_token_byte(byte) {
            start.get_or_insert(index);
        } else if let Some(value) = start.take()
            && index.saturating_sub(value) >= minimum
        {
            ranges.push((value, index));
        }
    }
    if let Some(value) = start
        && bytes.len().saturating_sub(value) >= minimum
    {
        ranges.push((value, bytes.len()));
    }
    ranges
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b'+' | b'=')
}

fn scan_token_end(bytes: &[u8], start: usize, quote: Option<u8>) -> usize {
    bytes[start..]
        .iter()
        .position(|byte| {
            if matches!(quote, Some(b'\'' | b'"')) {
                Some(*byte) == quote
            } else {
                byte.is_ascii_whitespace() || matches!(*byte, b',' | b';' | b'}' | b']')
            }
        })
        .map_or(bytes.len(), |relative| start + relative)
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    let mut counts = BTreeMap::<u8, usize>::new();
    for byte in bytes {
        *counts.entry(*byte).or_default() += 1;
    }
    let length = bytes.len() as f64;
    counts
        .values()
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn redact(input: &str, findings: &[SecretFinding]) -> SecurityResult<String> {
    let mut ranges = findings
        .iter()
        .map(|finding| (finding.start, finding.end, finding.class))
        .collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|(start, end, _)| (*start, *end));
    let mut merged = Vec::<(usize, usize, SecretClass)>::new();
    for (start, end, class) in ranges {
        if !input.is_char_boundary(start) || !input.is_char_boundary(end) || start >= end {
            return Err(SecurityError::IntegrityFailure(
                "secret scanner returned an invalid UTF-8 span".to_owned(),
            ));
        }
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end, class));
    }
    let mut output = input.to_owned();
    for (start, end, class) in merged.into_iter().rev() {
        output.replace_range(start..end, &format!("[REDACTED:{class:?}]"));
    }
    Ok(output)
}

fn is_vault_reference(input: &str) -> bool {
    let Some(reference) = input.strip_prefix("vault://") else {
        return false;
    };
    require_label(input, "vault_reference").is_ok()
        && !reference.is_empty()
        && reference.len() <= 500
        && reference.split('/').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn keyed_secret_digest(bytes: &[u8], key: &SecretDigestKey) -> String {
    let mut hasher = blake3::Hasher::new_keyed(&key.bytes);
    hasher.update(SECRET_DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}
