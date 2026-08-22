use serde::{Deserialize, Serialize};

use crate::{
    BackupSigningKey, BackupVerifyingKey, SecurityError, SecurityResult, canonical_json, digest,
    require_label,
};

const AUDIT_SIGNATURE_DOMAIN: &[u8] = b"contextdb/security-audit/v1\0";
const AUDIT_CHECKPOINT_SIGNATURE_DOMAIN: &[u8] = b"contextdb/security-audit-checkpoint/v1\0";
const GENESIS_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Security-relevant operation class. Payload content is deliberately absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Authorization or policy decision.
    Authorize,
    /// Raw evidence materialization.
    ReadEvidence,
    /// External model-provider invocation.
    ModelCall,
    /// Archive or handoff export.
    Export,
    /// Backup restore.
    Restore,
    /// Hard deletion or deletion retry.
    Delete,
    /// Administrative maintenance operation.
    Admin,
    /// Secret detection and policy application.
    SecretPolicy,
    /// Admission-control decision.
    Admission,
}

/// Stable result of a security policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    /// Operation was explicitly allowed.
    Allow,
    /// Operation was denied before content access.
    Deny,
    /// Operation completed with a bounded degraded result.
    Degraded,
}

/// Content-free canonical security audit event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditEvent {
    /// Host-supplied logical time.
    pub timestamp_micros: i64,
    /// One-way actor identifier digest.
    pub actor_digest: String,
    /// Optional one-way agent identifier digest.
    pub agent_digest: Option<String>,
    /// Operation class.
    pub action: AuditAction,
    /// Bounded resource class, never a raw resource identifier.
    pub resource_class: String,
    /// Bounded purpose label.
    pub purpose: String,
    /// Policy result.
    pub decision: AuditDecision,
    /// Digest of exact authorized scopes.
    pub scope_digest: String,
    /// Whether separately-authorized raw evidence was materialized.
    pub raw_evidence_access: bool,
    /// Optional provider-profile digest, never provider input/output.
    pub provider_digest: Option<String>,
    /// Optional signed export/backup manifest digest.
    pub export_manifest_digest: Option<String>,
    /// Optional deletion workflow identifier.
    pub deletion_id: Option<String>,
    /// Privacy-safe trace identifier.
    pub trace_id: String,
}

impl SecurityAuditEvent {
    /// Validates size and digest constraints without inspecting protected data.
    pub fn validate(&self) -> SecurityResult<()> {
        require_digest(&self.actor_digest, "actor_digest")?;
        if let Some(value) = &self.agent_digest {
            require_digest(value, "agent_digest")?;
        }
        require_label(&self.resource_class, "resource_class")?;
        require_label(&self.purpose, "purpose")?;
        require_digest(&self.scope_digest, "scope_digest")?;
        for (value, name) in [
            (&self.provider_digest, "provider_digest"),
            (&self.export_manifest_digest, "export_manifest_digest"),
        ] {
            if let Some(value) = value {
                require_digest(value, name)?;
            }
        }
        if let Some(value) = &self.deletion_id {
            require_label(value, "deletion_id")?;
        }
        require_label(&self.trace_id, "trace_id")
    }
}

/// Signed append-only audit entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    /// One-based chain position.
    pub sequence: u64,
    /// Chain identity.
    pub chain_id: String,
    /// Previous entry digest or the all-zero genesis digest.
    pub previous_digest: String,
    /// Canonical event.
    pub event: SecurityAuditEvent,
    /// Digest of sequence, chain, previous digest, and event.
    pub entry_digest: String,
    /// Signing-key identifier.
    pub signing_key_id: String,
    /// Ed25519 signature over the entry digest in an audit-specific domain.
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct UnsignedEntry<'a> {
    sequence: u64,
    chain_id: &'a str,
    previous_digest: &'a str,
    event: &'a SecurityAuditEvent,
}

/// Externally anchored signed head of an audit chain. Persisting the newest
/// checkpoint outside the mutable audit log makes suffix truncation detectable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditCheckpoint {
    /// Chain identity.
    pub chain_id: String,
    /// Number of entries covered by this checkpoint.
    pub sequence: u64,
    /// Covered head digest, or the genesis digest for an empty chain.
    pub entry_digest: String,
    /// Signing-key identifier.
    pub signing_key_id: String,
    /// Domain-separated Ed25519 signature over the canonical checkpoint.
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct UnsignedCheckpoint<'a> {
    chain_id: &'a str,
    sequence: u64,
    entry_digest: &'a str,
}

/// Deterministic append-only audit chain reference implementation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditChain {
    chain_id: String,
    entries: Vec<AuditEntry>,
}

impl SecurityAuditChain {
    /// Creates an empty chain.
    pub fn new(chain_id: impl Into<String>) -> SecurityResult<Self> {
        let chain_id = chain_id.into();
        require_label(&chain_id, "chain_id")?;
        Ok(Self {
            chain_id,
            entries: Vec::new(),
        })
    }

    /// Returns immutable entries for durable persistence by the host.
    #[must_use]
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Signs the current head for persistence in an independent durable
    /// control-plane anchor. An audit log without its latest external
    /// checkpoint can prove link integrity but cannot prove suffix presence.
    pub fn checkpoint(
        &self,
        signing_key: &BackupSigningKey,
    ) -> SecurityResult<SecurityAuditCheckpoint> {
        require_label(&self.chain_id, "chain_id")?;
        let sequence = u64::try_from(self.entries.len())
            .map_err(|_| SecurityError::ResourceExhausted("audit sequence overflow".to_owned()))?;
        let entry_digest = self
            .entries
            .last()
            .map_or(GENESIS_DIGEST, |entry| entry.entry_digest.as_str());
        require_digest(entry_digest, "audit_checkpoint.entry_digest")?;
        let unsigned = UnsignedCheckpoint {
            chain_id: &self.chain_id,
            sequence,
            entry_digest,
        };
        let bytes = canonical_json(&unsigned)?;
        Ok(SecurityAuditCheckpoint {
            chain_id: self.chain_id.clone(),
            sequence,
            entry_digest: entry_digest.to_owned(),
            signing_key_id: signing_key.key_id().to_owned(),
            signature: signing_key.sign_domain(AUDIT_CHECKPOINT_SIGNATURE_DOMAIN, &bytes),
        })
    }

    /// Appends one signed content-free event.
    pub fn append(
        &mut self,
        event: SecurityAuditEvent,
        signing_key: &BackupSigningKey,
    ) -> SecurityResult<&AuditEntry> {
        event.validate()?;
        if self
            .entries
            .last()
            .is_some_and(|entry| event.timestamp_micros < entry.event.timestamp_micros)
        {
            return Err(SecurityError::IntegrityFailure(
                "security audit time regressed".to_owned(),
            ));
        }
        let sequence = u64::try_from(self.entries.len())
            .map_err(|_| SecurityError::ResourceExhausted("audit sequence overflow".to_owned()))?
            .checked_add(1)
            .ok_or_else(|| {
                SecurityError::ResourceExhausted("audit sequence overflow".to_owned())
            })?;
        let previous_digest = self.entries.last().map_or_else(
            || GENESIS_DIGEST.to_owned(),
            |entry| entry.entry_digest.clone(),
        );
        let unsigned = UnsignedEntry {
            sequence,
            chain_id: &self.chain_id,
            previous_digest: &previous_digest,
            event: &event,
        };
        let entry_digest = digest(&canonical_json(&unsigned)?);
        let signature = signing_key.sign_domain(AUDIT_SIGNATURE_DOMAIN, entry_digest.as_bytes());
        self.entries.push(AuditEntry {
            sequence,
            chain_id: self.chain_id.clone(),
            previous_digest,
            event,
            entry_digest,
            signing_key_id: signing_key.key_id().to_owned(),
            signature,
        });
        self.entries.last().ok_or_else(|| {
            SecurityError::IntegrityFailure("audit append was not visible".to_owned())
        })
    }

    /// Deep-verifies every chain link, canonical digest, and signature.
    pub fn verify(&self, verifying_key: &BackupVerifyingKey) -> SecurityResult<()> {
        require_label(&self.chain_id, "chain_id")?;
        let mut previous = GENESIS_DIGEST.to_owned();
        let mut previous_time = None;
        for (index, entry) in self.entries.iter().enumerate() {
            entry.event.validate()?;
            let expected_sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    SecurityError::IntegrityFailure("audit sequence overflow".to_owned())
                })?;
            if entry.sequence != expected_sequence
                || entry.chain_id != self.chain_id
                || entry.previous_digest != previous
                || entry.signing_key_id != verifying_key.key_id
                || previous_time.is_some_and(|time| entry.event.timestamp_micros < time)
            {
                return Err(SecurityError::IntegrityFailure(
                    "audit chain metadata mismatch".to_owned(),
                ));
            }
            let unsigned = UnsignedEntry {
                sequence: entry.sequence,
                chain_id: &entry.chain_id,
                previous_digest: &entry.previous_digest,
                event: &entry.event,
            };
            let expected_digest = digest(&canonical_json(&unsigned)?);
            if expected_digest != entry.entry_digest {
                return Err(SecurityError::IntegrityFailure(
                    "audit entry digest mismatch".to_owned(),
                ));
            }
            verifying_key.verify_domain(
                AUDIT_SIGNATURE_DOMAIN,
                entry.entry_digest.as_bytes(),
                &entry.signature,
            )?;
            previous.clone_from(&entry.entry_digest);
            previous_time = Some(entry.event.timestamp_micros);
        }
        Ok(())
    }

    /// Verifies every entry and requires an independently retained signed head.
    /// This is the release-grade verification path because it detects a valid
    /// signed prefix presented after the original tail was removed.
    pub fn verify_against_checkpoint(
        &self,
        checkpoint: &SecurityAuditCheckpoint,
        verifying_key: &BackupVerifyingKey,
    ) -> SecurityResult<()> {
        self.verify(verifying_key)?;
        require_label(&checkpoint.chain_id, "audit_checkpoint.chain_id")?;
        require_digest(&checkpoint.entry_digest, "audit_checkpoint.entry_digest")?;
        if checkpoint.signing_key_id != verifying_key.key_id {
            return Err(SecurityError::IntegrityFailure(
                "audit checkpoint signing-key identity mismatch".to_owned(),
            ));
        }
        let expected_sequence = u64::try_from(self.entries.len())
            .map_err(|_| SecurityError::ResourceExhausted("audit sequence overflow".to_owned()))?;
        let expected_digest = self
            .entries
            .last()
            .map_or(GENESIS_DIGEST, |entry| entry.entry_digest.as_str());
        if checkpoint.chain_id != self.chain_id
            || checkpoint.sequence != expected_sequence
            || checkpoint.entry_digest != expected_digest
        {
            return Err(SecurityError::IntegrityFailure(
                "audit checkpoint does not match the complete chain head".to_owned(),
            ));
        }
        let unsigned = UnsignedCheckpoint {
            chain_id: &checkpoint.chain_id,
            sequence: checkpoint.sequence,
            entry_digest: &checkpoint.entry_digest,
        };
        let bytes = canonical_json(&unsigned)?;
        verifying_key.verify_domain(
            AUDIT_CHECKPOINT_SIGNATURE_DOMAIN,
            &bytes,
            &checkpoint.signature,
        )
    }
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
