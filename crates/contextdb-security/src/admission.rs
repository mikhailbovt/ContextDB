use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{SecurityError, SecurityResult, require_label};

/// Maximum serialized admission state accepted before JSON allocation.
pub const MAX_ADMISSION_STATE_BYTES: usize = 1024 * 1024;

/// Per-request resource claim evaluated before expensive work begins.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceClaim {
    /// Stable idempotent request identity.
    pub request_id: String,
    /// Tenant/workspace identity used only in the local admission partition.
    pub workspace_id: String,
    /// Input bytes.
    pub input_bytes: u64,
    /// Maximum recall candidates.
    pub candidates: u64,
    /// Maximum graph frontier entries.
    pub frontier: u64,
    /// Maximum graph hops.
    pub graph_hops: u64,
    /// Maximum model attempts including repair.
    pub model_attempts: u64,
    /// Requested snapshot lifetime.
    pub snapshot_ttl_millis: u64,
}

impl fmt::Debug for ResourceClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceClaim")
            .field("request_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("input_bytes", &self.input_bytes)
            .field("candidates", &self.candidates)
            .field("frontier", &self.frontier)
            .field("graph_hops", &self.graph_hops)
            .field("model_attempts", &self.model_attempts)
            .field("snapshot_ttl_millis", &self.snapshot_ttl_millis)
            .finish()
    }
}

/// Hard admission limits for one workspace partition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Maximum simultaneously admitted requests per workspace.
    pub concurrent_requests: u64,
    /// Maximum total input bytes in flight per workspace.
    pub inflight_bytes: u64,
    /// Maximum input bytes for one request.
    pub request_bytes: u64,
    /// Maximum candidates for one request.
    pub candidates: u64,
    /// Maximum frontier entries for one request.
    pub frontier: u64,
    /// Maximum graph hops for one request.
    pub graph_hops: u64,
    /// Maximum model attempts for one request.
    pub model_attempts: u64,
    /// Maximum retained snapshot lifetime.
    pub snapshot_ttl_millis: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            concurrent_requests: 32,
            inflight_bytes: 32 * 1024 * 1024,
            request_bytes: 16 * 1024 * 1024,
            candidates: 10_000,
            frontier: 100_000,
            graph_hops: 8,
            model_attempts: 3,
            snapshot_ttl_millis: 5 * 60 * 1_000,
        }
    }
}

/// Deterministic workspace-partitioned admission state. The host may wrap it
/// in a mutex or actor; no hidden global state exists.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveLease {
    claim: ResourceClaim,
    admitted_at_millis: u64,
    expires_at_millis: u64,
}

/// Bounded wire form parsed only after the byte-size admission check.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionStateWire {
    active: BTreeMap<String, BTreeMap<String, ActiveLease>>,
    last_observed_millis: u64,
}

/// Deterministic workspace-partitioned controller with bounded expiring
/// leases. Hosts supply a monotonic logical clock; no hidden timer exists.
#[derive(Clone, Default, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionController {
    active: BTreeMap<String, BTreeMap<String, ActiveLease>>,
    last_observed_millis: u64,
}

impl fmt::Debug for AdmissionController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let request_count = self.active.values().map(BTreeMap::len).sum::<usize>();
        formatter
            .debug_struct("AdmissionController")
            .field("workspace_count", &self.active.len())
            .field("request_count", &request_count)
            .finish_non_exhaustive()
    }
}

impl AdmissionController {
    /// Admits an exact claim or returns fail-closed backpressure. Replaying an
    /// identical request is idempotent; changing the same request ID conflicts.
    pub fn admit(
        &mut self,
        claim: ResourceClaim,
        limits: &ResourceLimits,
        now_millis: u64,
    ) -> SecurityResult<()> {
        self.reap_expired(now_millis)?;
        validate_claim(&claim, limits)?;
        let workspace = self.active.entry(claim.workspace_id.clone()).or_default();
        validate_workspace(&claim.workspace_id, workspace, limits, now_millis)?;
        if let Some(existing) = workspace.get(&claim.request_id) {
            if existing.claim == claim {
                return Ok(());
            }
            return Err(SecurityError::InvalidInput(
                "admission request ID was reused with a different resource claim".to_owned(),
            ));
        }
        let active_count = u64::try_from(workspace.len()).unwrap_or(u64::MAX);
        if active_count >= limits.concurrent_requests {
            return Err(SecurityError::ResourceExhausted(
                "workspace concurrent request quota".to_owned(),
            ));
        }
        let active_bytes = workspace.values().try_fold(0_u64, |total, active| {
            total.checked_add(active.claim.input_bytes).ok_or_else(|| {
                SecurityError::ResourceExhausted("workspace in-flight byte overflow".to_owned())
            })
        })?;
        if active_bytes
            .checked_add(claim.input_bytes)
            .is_none_or(|total| total > limits.inflight_bytes)
        {
            return Err(SecurityError::ResourceExhausted(
                "workspace in-flight byte quota".to_owned(),
            ));
        }
        let expires_at_millis = now_millis
            .checked_add(claim.snapshot_ttl_millis)
            .ok_or_else(|| {
                SecurityError::ResourceExhausted("admission lease overflow".to_owned())
            })?;
        workspace.insert(
            claim.request_id.clone(),
            ActiveLease {
                claim,
                admitted_at_millis: now_millis,
                expires_at_millis,
            },
        );
        Ok(())
    }

    /// Releases an admitted request. Unknown release IDs fail closed so leaks
    /// in host accounting cannot be silently hidden.
    pub fn release(&mut self, workspace_id: &str, request_id: &str) -> SecurityResult<()> {
        let workspace = self
            .active
            .get_mut(workspace_id)
            .ok_or_else(|| SecurityError::InvalidInput("unknown admission workspace".to_owned()))?;
        if workspace.remove(request_id).is_none() {
            return Err(SecurityError::InvalidInput(
                "unknown admitted request".to_owned(),
            ));
        }
        if workspace.is_empty() {
            self.active.remove(workspace_id);
        }
        Ok(())
    }

    /// Returns active request IDs without their resource payloads.
    pub fn active_request_ids(
        &mut self,
        workspace_id: &str,
        now_millis: u64,
    ) -> SecurityResult<BTreeSet<String>> {
        self.reap_expired(now_millis)?;
        Ok(self
            .active
            .get(workspace_id)
            .map(|workspace| workspace.keys().cloned().collect())
            .unwrap_or_default())
    }

    /// Deep-validates deserialized accounting state against one exact limit
    /// profile. Hosts with per-workspace profiles call this once per matching
    /// partition before accepting restored state.
    pub fn validate(&self, limits: &ResourceLimits, now_millis: u64) -> SecurityResult<()> {
        validate_limits(limits)?;
        if now_millis < self.last_observed_millis {
            return Err(SecurityError::IntegrityFailure(
                "admission logical time regressed".to_owned(),
            ));
        }
        for (workspace_id, workspace) in &self.active {
            validate_workspace(workspace_id, workspace, limits, now_millis)?;
        }
        Ok(())
    }

    /// Serializes bounded lease state for a crash checkpoint.
    pub fn to_json(&self, limits: &ResourceLimits, now_millis: u64) -> SecurityResult<Vec<u8>> {
        self.validate(limits, now_millis)?;
        let bytes = serde_json::to_vec(self).map_err(|_| SecurityError::Serialization)?;
        if bytes.len() > MAX_ADMISSION_STATE_BYTES {
            return Err(SecurityError::ResourceExhausted(
                "serialized admission state exceeds byte budget".to_owned(),
            ));
        }
        Ok(bytes)
    }

    /// Parses admission state only after a hard byte bound, validates every
    /// partition, and discards leases that expired while the host was down.
    pub fn from_json_bounded(
        bytes: &[u8],
        limits: &ResourceLimits,
        now_millis: u64,
    ) -> SecurityResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_ADMISSION_STATE_BYTES {
            return Err(SecurityError::ResourceExhausted(
                "serialized admission state exceeds byte budget".to_owned(),
            ));
        }
        let wire: AdmissionStateWire =
            serde_json::from_slice(bytes).map_err(|_| SecurityError::Serialization)?;
        let mut controller = Self {
            active: wire.active,
            last_observed_millis: wire.last_observed_millis,
        };
        controller.reap_expired(now_millis)?;
        controller.validate(limits, now_millis)?;
        Ok(controller)
    }

    fn reap_expired(&mut self, now_millis: u64) -> SecurityResult<()> {
        if now_millis < self.last_observed_millis {
            return Err(SecurityError::IntegrityFailure(
                "admission logical time regressed".to_owned(),
            ));
        }
        self.last_observed_millis = now_millis;
        self.active.retain(|_, workspace| {
            workspace.retain(|_, lease| lease.expires_at_millis > now_millis);
            !workspace.is_empty()
        });
        Ok(())
    }
}

fn validate_claim(claim: &ResourceClaim, limits: &ResourceLimits) -> SecurityResult<()> {
    require_label(&claim.request_id, "request_id")?;
    require_label(&claim.workspace_id, "workspace_id")?;
    validate_limits(limits)?;
    for (actual, maximum, name) in [
        (claim.input_bytes, limits.request_bytes, "request bytes"),
        (claim.candidates, limits.candidates, "candidate budget"),
        (claim.frontier, limits.frontier, "frontier budget"),
        (claim.graph_hops, limits.graph_hops, "graph hop budget"),
        (
            claim.model_attempts,
            limits.model_attempts,
            "model attempt budget",
        ),
        (
            claim.snapshot_ttl_millis,
            limits.snapshot_ttl_millis,
            "snapshot TTL",
        ),
    ] {
        if actual > maximum || (name == "snapshot TTL" && actual == 0) {
            return Err(SecurityError::ResourceExhausted(name.to_owned()));
        }
    }
    Ok(())
}

fn validate_limits(limits: &ResourceLimits) -> SecurityResult<()> {
    if limits.concurrent_requests == 0 || limits.inflight_bytes == 0 || limits.request_bytes == 0 {
        return Err(SecurityError::InvalidInput(
            "resource limits cannot disable all admission".to_owned(),
        ));
    }
    if limits.request_bytes > limits.inflight_bytes {
        return Err(SecurityError::InvalidInput(
            "per-request byte limit exceeds workspace in-flight limit".to_owned(),
        ));
    }
    Ok(())
}

fn validate_workspace(
    workspace_id: &str,
    workspace: &BTreeMap<String, ActiveLease>,
    limits: &ResourceLimits,
    now_millis: u64,
) -> SecurityResult<()> {
    require_label(workspace_id, "workspace_id")?;
    let active_count = u64::try_from(workspace.len()).map_err(|_| {
        SecurityError::ResourceExhausted("workspace request count overflow".to_owned())
    })?;
    if active_count > limits.concurrent_requests {
        return Err(SecurityError::ResourceExhausted(
            "workspace concurrent request quota".to_owned(),
        ));
    }
    let mut active_bytes = 0_u64;
    for (request_id, lease) in workspace {
        validate_claim(&lease.claim, limits)?;
        if lease.claim.workspace_id != workspace_id || lease.claim.request_id != *request_id {
            return Err(SecurityError::IntegrityFailure(
                "admission partition identity mismatch".to_owned(),
            ));
        }
        if lease.expires_at_millis <= lease.admitted_at_millis
            || lease
                .admitted_at_millis
                .checked_add(lease.claim.snapshot_ttl_millis)
                != Some(lease.expires_at_millis)
            || lease.expires_at_millis <= now_millis
        {
            return Err(SecurityError::IntegrityFailure(
                "admission lease timing is invalid or expired".to_owned(),
            ));
        }
        active_bytes = active_bytes
            .checked_add(lease.claim.input_bytes)
            .ok_or_else(|| {
                SecurityError::ResourceExhausted("workspace in-flight byte overflow".to_owned())
            })?;
    }
    if active_bytes > limits.inflight_bytes {
        return Err(SecurityError::ResourceExhausted(
            "workspace in-flight byte quota".to_owned(),
        ));
    }
    Ok(())
}
