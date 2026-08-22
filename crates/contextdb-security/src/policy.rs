use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    BackupSigningKey, BackupVerifyingKey, SecurityError, SecurityResult, canonical_json, digest,
    require_label,
};

const LIVE_POLICY_CHECKPOINT_DOMAIN: &[u8] = b"contextdb/live-policy-checkpoint/v1\0";

/// Why an identity is denied by the live policy overlay.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveDenyReason {
    /// Hard deletion was authorized.
    HardDelete,
    /// Consent was revoked or expired.
    ConsentRevoked,
    /// Subject requested suppression without physical deletion.
    Suppressed,
    /// Retention expired.
    RetentionExpired,
    /// Security policy quarantined the identity.
    SecurityQuarantine,
}

/// One immutable live-policy transition.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LivePolicyTransition {
    /// Monotonic overlay generation.
    pub generation: u64,
    /// Identity denied or released.
    pub identity: String,
    /// New deny reason, or `None` for an explicitly authorized release.
    pub reason: Option<LiveDenyReason>,
    /// Current policy digest.
    pub policy_digest: String,
    /// Logical transition time.
    pub at_micros: i64,
}

impl fmt::Debug for LivePolicyTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LivePolicyTransition")
            .field("generation", &self.generation)
            .field("identity", &"[REDACTED]")
            .field("reason", &self.reason)
            .field("policy_digest", &"[REDACTED]")
            .field("at_micros", &self.at_micros)
            .finish()
    }
}

/// Signed exact head of a live-policy overlay, retained outside restoreable
/// data so stale-but-valid overlays cannot be replayed.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LivePolicyCheckpoint {
    /// Logical database identity.
    pub database_id: String,
    /// Workspace identity.
    pub workspace_id: String,
    /// Exact overlay generation.
    pub generation: u64,
    /// Digest of the complete canonical overlay state.
    pub overlay_digest: String,
    /// Signing-key identity.
    pub signing_key_id: String,
    /// Monotonic signing-key generation.
    pub signing_key_generation: u64,
    /// Domain-separated signature over the canonical checkpoint payload.
    pub signature: Vec<u8>,
}

impl fmt::Debug for LivePolicyCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LivePolicyCheckpoint")
            .field("database_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("generation", &self.generation)
            .field("overlay_digest", &"[REDACTED]")
            .field("signing_key_id", &self.signing_key_id)
            .field("signing_key_generation", &self.signing_key_generation)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct UnsignedPolicyCheckpoint<'a> {
    database_id: &'a str,
    workspace_id: &'a str,
    generation: u64,
    overlay_digest: &'a str,
    signing_key_id: &'a str,
    signing_key_generation: u64,
}

/// Current authorization/deletion overlay consulted even for old snapshots.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LivePolicyOverlay {
    database_id: String,
    workspace_id: String,
    generation: u64,
    denied: BTreeMap<String, LiveDenyReason>,
    transitions: Vec<LivePolicyTransition>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedLivePolicyOverlay {
    database_id: String,
    workspace_id: String,
    generation: u64,
    denied: BTreeMap<String, LiveDenyReason>,
    transitions: Vec<LivePolicyTransition>,
}

impl<'de> Deserialize<'de> for LivePolicyOverlay {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedLivePolicyOverlay::deserialize(deserializer)?;
        let overlay = Self {
            database_id: unchecked.database_id,
            workspace_id: unchecked.workspace_id,
            generation: unchecked.generation,
            denied: unchecked.denied,
            transitions: unchecked.transitions,
        };
        overlay.validate().map_err(serde::de::Error::custom)?;
        Ok(overlay)
    }
}

impl fmt::Debug for LivePolicyOverlay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LivePolicyOverlay")
            .field("database_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("generation", &self.generation)
            .field("denied_count", &self.denied.len())
            .field("transition_count", &self.transitions.len())
            .finish_non_exhaustive()
    }
}

impl LivePolicyOverlay {
    /// Creates an empty overlay bound to one logical database and workspace.
    pub fn new(
        database_id: impl Into<String>,
        workspace_id: impl Into<String>,
    ) -> SecurityResult<Self> {
        let overlay = Self {
            database_id: database_id.into(),
            workspace_id: workspace_id.into(),
            generation: 0,
            denied: BTreeMap::new(),
            transitions: Vec::new(),
        };
        overlay.validate()?;
        Ok(overlay)
    }

    /// Logical database to which this live overlay belongs.
    #[must_use]
    pub fn database_id(&self) -> &str {
        &self.database_id
    }

    /// Workspace to which this live overlay belongs.
    #[must_use]
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    /// Current monotonic generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Content-free transition history for audit/replay.
    #[must_use]
    pub fn transitions(&self) -> &[LivePolicyTransition] {
        &self.transitions
    }

    /// Identities currently denied.
    #[must_use]
    pub fn denied_identities(&self) -> BTreeSet<&str> {
        self.denied.keys().map(String::as_str).collect()
    }

    /// Signs the complete current overlay for an independent durable anchor.
    pub fn checkpoint(
        &self,
        signing_key: &BackupSigningKey,
    ) -> SecurityResult<LivePolicyCheckpoint> {
        self.validate()?;
        let overlay_digest = digest(&canonical_json(self)?);
        let unsigned = UnsignedPolicyCheckpoint {
            database_id: &self.database_id,
            workspace_id: &self.workspace_id,
            generation: self.generation,
            overlay_digest: &overlay_digest,
            signing_key_id: signing_key.key_id(),
            signing_key_generation: signing_key.generation(),
        };
        let signature =
            signing_key.sign_domain(LIVE_POLICY_CHECKPOINT_DOMAIN, &canonical_json(&unsigned)?);
        Ok(LivePolicyCheckpoint {
            database_id: self.database_id.clone(),
            workspace_id: self.workspace_id.clone(),
            generation: self.generation,
            overlay_digest,
            signing_key_id: signing_key.key_id().to_owned(),
            signing_key_generation: signing_key.generation(),
            signature,
        })
    }

    /// Proves exact domain, generation, and full state against an externally
    /// retained checkpoint before any authorization decision.
    pub fn verify_checkpoint(
        &self,
        checkpoint: &LivePolicyCheckpoint,
        verifying_key: &BackupVerifyingKey,
    ) -> SecurityResult<()> {
        self.validate()?;
        require_label(
            &checkpoint.database_id,
            "live_policy_checkpoint.database_id",
        )?;
        require_label(
            &checkpoint.workspace_id,
            "live_policy_checkpoint.workspace_id",
        )?;
        require_digest(
            &checkpoint.overlay_digest,
            "live_policy_checkpoint.overlay_digest",
        )?;
        let expected_digest = digest(&canonical_json(self)?);
        if checkpoint.database_id != self.database_id
            || checkpoint.workspace_id != self.workspace_id
            || checkpoint.generation != self.generation
            || checkpoint.overlay_digest != expected_digest
            || checkpoint.signing_key_id != verifying_key.key_id
            || checkpoint.signing_key_generation != verifying_key.generation
            || checkpoint.signing_key_generation == 0
        {
            return Err(SecurityError::IntegrityFailure(
                "live policy checkpoint does not match exact current state".to_owned(),
            ));
        }
        let unsigned = UnsignedPolicyCheckpoint {
            database_id: &checkpoint.database_id,
            workspace_id: &checkpoint.workspace_id,
            generation: checkpoint.generation,
            overlay_digest: &checkpoint.overlay_digest,
            signing_key_id: &checkpoint.signing_key_id,
            signing_key_generation: checkpoint.signing_key_generation,
        };
        verifying_key.verify_domain(
            LIVE_POLICY_CHECKPOINT_DOMAIN,
            &canonical_json(&unsigned)?,
            &checkpoint.signature,
        )
    }

    /// Denies an identity before derived cleanup starts. Exact replay at the
    /// same generation is accepted; all other generation reuse fails closed.
    pub fn deny(
        &mut self,
        identity: impl Into<String>,
        reason: LiveDenyReason,
        policy_digest: impl Into<String>,
        at_micros: i64,
    ) -> SecurityResult<u64> {
        self.validate()?;
        let identity = identity.into();
        let policy_digest = policy_digest.into();
        require_label(&identity, "live_policy.identity")?;
        require_digest(&policy_digest, "live_policy.policy_digest")?;
        if self.denied.get(&identity) == Some(&LiveDenyReason::HardDelete)
            && reason != LiveDenyReason::HardDelete
        {
            return Err(SecurityError::PolicyDenied(
                "hard-deleted identity cannot be weakened".to_owned(),
            ));
        }
        if self.denied.get(&identity) == Some(&reason)
            && self
                .transitions
                .iter()
                .rev()
                .find(|entry| entry.identity == identity)
                .is_some_and(|entry| {
                    entry.reason == Some(reason)
                        && entry.policy_digest == policy_digest
                        && entry.at_micros == at_micros
                })
        {
            return Ok(self.generation);
        }
        self.require_monotonic_time(at_micros)?;
        self.generation = self.generation.checked_add(1).ok_or_else(|| {
            SecurityError::ResourceExhausted("live policy generation overflow".to_owned())
        })?;
        self.denied.insert(identity.clone(), reason);
        self.transitions.push(LivePolicyTransition {
            generation: self.generation,
            identity,
            reason: Some(reason),
            policy_digest,
            at_micros,
        });
        Ok(self.generation)
    }

    /// Releases a non-deletion deny only after an independent policy decision.
    /// Hard-deleted identities can never be resurrected by an old archive.
    pub fn release(
        &mut self,
        identity: &str,
        policy_digest: impl Into<String>,
        at_micros: i64,
    ) -> SecurityResult<u64> {
        self.validate()?;
        require_label(identity, "live_policy.identity")?;
        let policy_digest = policy_digest.into();
        require_digest(&policy_digest, "live_policy.policy_digest")?;
        match self.denied.get(identity) {
            Some(LiveDenyReason::HardDelete) => {
                return Err(SecurityError::PolicyDenied(
                    "hard-deleted identity cannot be released".to_owned(),
                ));
            }
            Some(_) => {}
            None => {
                if self
                    .transitions
                    .iter()
                    .rev()
                    .find(|entry| entry.identity == identity)
                    .is_some_and(|entry| {
                        entry.reason.is_none()
                            && entry.policy_digest == policy_digest
                            && entry.at_micros == at_micros
                    })
                {
                    return Ok(self.generation);
                }
                return Err(SecurityError::InvalidInput(
                    "live policy cannot release an identity that is not denied".to_owned(),
                ));
            }
        }
        self.require_monotonic_time(at_micros)?;
        self.generation = self.generation.checked_add(1).ok_or_else(|| {
            SecurityError::ResourceExhausted("live policy generation overflow".to_owned())
        })?;
        self.denied.remove(identity);
        self.transitions.push(LivePolicyTransition {
            generation: self.generation,
            identity: identity.to_owned(),
            reason: None,
            policy_digest,
            at_micros,
        });
        Ok(self.generation)
    }

    /// Authorizes identity use before candidate generation. The supplied
    /// snapshot generation is intentionally ignored for deny decisions: the
    /// current overlay always wins.
    pub fn authorize_before_candidate(
        &self,
        identity: &str,
        _snapshot_generation: u64,
        checkpoint: &LivePolicyCheckpoint,
        verifying_key: &BackupVerifyingKey,
    ) -> SecurityResult<()> {
        self.verify_checkpoint(checkpoint, verifying_key)?;
        require_label(identity, "live_policy.identity")?;
        if let Some(reason) = self.denied.get(identity) {
            return Err(SecurityError::PolicyDenied(format!(
                "live policy denies identity: {reason:?}"
            )));
        }
        Ok(())
    }

    /// Merges an externally durable overlay into a restored database. A deny
    /// always dominates an absent or weaker restored state.
    pub fn apply_to_restore(
        &self,
        restored: &mut Self,
        checkpoint: &LivePolicyCheckpoint,
        verifying_key: &BackupVerifyingKey,
    ) -> SecurityResult<()> {
        self.verify_checkpoint(checkpoint, verifying_key)?;
        restored.validate()?;
        if self.database_id != restored.database_id || self.workspace_id != restored.workspace_id {
            return Err(SecurityError::PolicyDenied(
                "live policy overlay binding does not match restore target".to_owned(),
            ));
        }
        let mut candidate = restored.clone();
        for transition in &self.transitions {
            match transition.reason {
                Some(reason) => {
                    candidate.deny(
                        transition.identity.clone(),
                        reason,
                        transition.policy_digest.clone(),
                        transition.at_micros,
                    )?;
                }
                None => {
                    if candidate.denied.get(&transition.identity)
                        != Some(&LiveDenyReason::HardDelete)
                    {
                        candidate.release(
                            &transition.identity,
                            transition.policy_digest.clone(),
                            transition.at_micros,
                        )?;
                    }
                }
            }
        }
        candidate.validate()?;
        *restored = candidate;
        Ok(())
    }

    /// Deep-validates a serialized overlay by reconstructing its current deny
    /// set from the immutable transition sequence.
    pub fn validate(&self) -> SecurityResult<()> {
        require_label(&self.database_id, "live_policy.database_id")?;
        require_label(&self.workspace_id, "live_policy.workspace_id")?;
        let expected_generation = u64::try_from(self.transitions.len()).map_err(|_| {
            SecurityError::ResourceExhausted("live policy generation overflow".to_owned())
        })?;
        if self.generation != expected_generation {
            return Err(SecurityError::IntegrityFailure(
                "live policy generation does not match transition history".to_owned(),
            ));
        }
        let mut reconstructed = BTreeMap::new();
        let mut previous_time = None;
        for (index, transition) in self.transitions.iter().enumerate() {
            let expected = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    SecurityError::ResourceExhausted("live policy generation overflow".to_owned())
                })?;
            require_label(&transition.identity, "live_policy.identity")?;
            require_digest(&transition.policy_digest, "live_policy.policy_digest")?;
            if transition.generation != expected
                || previous_time.is_some_and(|time| transition.at_micros < time)
            {
                return Err(SecurityError::IntegrityFailure(
                    "live policy transition ordering is invalid".to_owned(),
                ));
            }
            match transition.reason {
                Some(reason) => {
                    if reconstructed.get(&transition.identity) == Some(&LiveDenyReason::HardDelete)
                        && reason != LiveDenyReason::HardDelete
                    {
                        return Err(SecurityError::IntegrityFailure(
                            "live policy history weakens a hard deletion".to_owned(),
                        ));
                    }
                    reconstructed.insert(transition.identity.clone(), reason);
                }
                None => {
                    if reconstructed.get(&transition.identity) == Some(&LiveDenyReason::HardDelete)
                        || reconstructed.remove(&transition.identity).is_none()
                    {
                        return Err(SecurityError::IntegrityFailure(
                            "live policy contains an invalid release".to_owned(),
                        ));
                    }
                }
            }
            previous_time = Some(transition.at_micros);
        }
        if reconstructed != self.denied {
            return Err(SecurityError::IntegrityFailure(
                "live policy current state does not match transition history".to_owned(),
            ));
        }
        Ok(())
    }

    fn require_monotonic_time(&self, at_micros: i64) -> SecurityResult<()> {
        if self
            .transitions
            .last()
            .is_some_and(|entry| at_micros < entry.at_micros)
        {
            return Err(SecurityError::IntegrityFailure(
                "live policy transition time regressed".to_owned(),
            ));
        }
        Ok(())
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
