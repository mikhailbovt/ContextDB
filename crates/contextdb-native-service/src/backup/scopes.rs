//! Explicit host authentication for independently retained archive scopes.

use std::{fmt, marker::PhantomData, rc::Rc};

use contextdb_recall::QueryBudget;
use contextdb_service::{AuthenticatedRequestContext, authorize_capability};
use serde::Serialize;

use super::*;
use crate::{NativeRemovalRequestReceipt, suppression::RemovalCheckpoint};

mod frames;

const MAX_WORKSPACES: usize = 64;
const MAX_SCOPE_BYTES: usize = 32 * 1024 * 1024;
pub(crate) type ArchiveRemovalFence = (
    std::sync::Arc<crate::NativeSuppressionLedger>,
    RemovalCheckpoint,
);

/// Host-only workspace allowlist and fresh authentication adapter. Configuration
/// supplies no grants. Never expose this handle as a model-facing tool argument.
pub struct NativeArchiveScopeResolver<'host> {
    configured: BTreeMap<String, String>,
    authority: &'host dyn NativeArchiveMaintenanceAuthority,
}

impl fmt::Debug for NativeArchiveScopeResolver<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeArchiveScopeResolver")
            .field("workspaces", &self.configured.len())
            .finish_non_exhaustive()
    }
}

impl<'host> NativeArchiveScopeResolver<'host> {
    /// Configure 1..64 exact workspace IDs without authenticating or opening data.
    pub fn new(
        workspaces: &[String],
        authority: &'host dyn NativeArchiveMaintenanceAuthority,
    ) -> ServiceResult<Self> {
        if !(1..=MAX_WORKSPACES).contains(&workspaces.len()) {
            return Err(crate::invalid("archive scopes require 1..64 workspaces"));
        }
        let mut configured = BTreeMap::new();
        for workspace in workspaces {
            if workspace.trim().is_empty() || workspace.len() > 1024 || workspace.contains('\0') {
                return Err(crate::invalid("archive workspace identifier is invalid"));
            }
            if configured
                .insert(digest_bytes(workspace.as_bytes()), workspace.clone())
                .is_some()
            {
                return Err(crate::invalid("archive workspaces must be distinct"));
            }
        }
        Ok(Self {
            configured,
            authority,
        })
    }

    pub(crate) fn context(
        &self,
        workspace: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AuthenticatedRequestContext> {
        let digest = digest_bytes(workspace.as_bytes());
        if self.configured.get(&digest).map(String::as_str) != Some(workspace) {
            return Err(scope_required());
        }
        budget.check().map_err(crate::raw_index::budget_error)?;
        let context = self.authority.context(workspace, budget)?;
        budget.check().map_err(crate::raw_index::budget_error)?;
        if context.request.workspace_id != workspace {
            return Err(crate::permission_denied());
        }
        authorize_capability(&context, Capability::Admin)?;
        let bytes = encode(&context)?;
        budget
            .charge(1, bytes.len() as u64)
            .map_err(crate::raw_index::budget_error)?;
        if bytes.len() > MAX_SCOPE_BYTES {
            return Err(exhausted("archive authentication metadata exceeds 32 MiB"));
        }
        Ok(context)
    }

    /// Fresh contexts remain inside one operation, never an accepted credential.
    pub(crate) fn verify(
        &self,
        owner: &NativeService,
        required: &[ArchiveScopeRequirement],
        budget: &mut QueryBudget,
    ) -> ServiceResult<VerifiedArchiveScopes> {
        self.verify_profile(owner, required, None, budget)
    }

    /// Scheduling may observe unavailable foreign authority, but cannot use its
    /// jobs or edges. The current workspace remains mandatory and exact.
    pub(crate) fn verify_available(
        &self,
        owner: &NativeService,
        required: &[ArchiveScopeRequirement],
        current: &ArchiveScopeRequirement,
        budget: &mut QueryBudget,
    ) -> ServiceResult<VerifiedArchiveScopes> {
        let frame =
            self.verify_profile(owner, required, Some(&current.workspace_digest), budget)?;
        frame.context_for(&current.workspace_digest, &current.request)?;
        Ok(frame)
    }

    fn verify_profile(
        &self,
        owner: &NativeService,
        required: &[ArchiveScopeRequirement],
        mandatory: Option<&str>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<VerifiedArchiveScopes> {
        if required.is_empty() {
            return Err(crate::invalid("archive scope requirements are empty"));
        }
        let ledger = owner
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("archive scope authority absent"))?;
        let mut requests = BTreeMap::new();
        let mut workspaces = BTreeSet::new();
        let mut total = 0usize;
        for requirement in required {
            budget.check().map_err(crate::raw_index::budget_error)?;
            if requirement.request.authority_id != ledger.authority_id() {
                return Err(integrity("archive scope crosses removal authority"));
            }
            if mandatory.is_none() && !self.configured.contains_key(&requirement.workspace_digest) {
                return Err(scope_required());
            }
            let bytes = encode(requirement)?;
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| exhausted("archive scope metadata size overflow"))?;
            budget
                .charge(1, bytes.len() as u64)
                .map_err(crate::raw_index::budget_error)?;
            if total > MAX_SCOPE_BYTES {
                return Err(exhausted("archive scope metadata exceeds 32 MiB"));
            }
            let key = (
                requirement.workspace_digest.clone(),
                requirement.request.authority_id,
                requirement.request.sequence,
            );
            if requests
                .insert(key, requirement.request.clone())
                .is_some_and(|previous| previous != requirement.request)
            {
                return Err(integrity(
                    "archive scope request has contradictory receipts",
                ));
            }
            workspaces.insert(requirement.workspace_digest.clone());
        }
        let mut contexts = BTreeMap::new();
        for digest in workspaces {
            let Some(workspace) = self.configured.get(&digest) else {
                if mandatory.is_some_and(|workspace| workspace != digest) {
                    continue;
                }
                return Err(scope_required());
            };
            let context = match self.context(workspace, budget) {
                Ok(context) => context,
                Err(error)
                    if mandatory.is_some_and(|workspace| workspace != digest)
                        && matches!(
                            error.code,
                            ErrorCode::Unauthorized | ErrorCode::EvidenceRequired
                        ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            total = total
                .checked_add(encode(&context)?.len())
                .ok_or_else(|| exhausted("archive scope metadata size overflow"))?;
            if total > MAX_SCOPE_BYTES {
                return Err(exhausted("archive scope metadata exceeds 32 MiB"));
            }
            contexts.insert(digest, context);
        }
        let first = contexts
            .values()
            .next()
            .ok_or_else(|| integrity("archive scope contexts absent"))?;
        let inventory = owner.read_original_removal_requests(first, budget)?;
        let removal_frontier = RemovalCheckpoint {
            sequence: inventory.sequence,
            digest: inventory.digest,
        };
        requests.retain(|(workspace, _, _), _| contexts.contains_key(workspace));
        for ((workspace, _, _), request) in &requests {
            let context = contexts
                .get(workspace)
                .ok_or_else(|| integrity("archive scope context disappeared"))?;
            owner.read_original_removal_inventory(context, request, budget)?;
        }
        ledger.require_removal_frontier(&removal_frontier, budget)?;
        Ok(VerifiedArchiveScopes {
            contexts,
            requests,
            removal_frontier,
            _thread: PhantomData,
        })
    }
}

/// Content-free requirements come from current exact requests and verified paths.
#[derive(Serialize)]
pub(crate) struct ArchiveScopeRequirement {
    pub(crate) workspace_digest: String,
    pub(crate) request: NativeRemovalRequestReceipt,
}

/// A fresh, thread-local operation frame. Neither serialized nor clonable.
pub(crate) struct VerifiedArchiveScopes {
    contexts: BTreeMap<String, AuthenticatedRequestContext>,
    requests: BTreeMap<(String, uuid::Uuid, u64), NativeRemovalRequestReceipt>,
    pub(crate) removal_frontier: RemovalCheckpoint,
    _thread: PhantomData<Rc<()>>,
}

impl VerifiedArchiveScopes {
    // Caller may already hold custody; this check does not acquire a queue.
    pub(crate) fn require_frontier(
        &self,
        owner: &NativeService,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        owner
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("archive scope authority absent"))?
            .require_removal_frontier(&self.removal_frontier, budget)
    }

    pub(crate) fn context_for(
        &self,
        workspace_digest: &str,
        request: &NativeRemovalRequestReceipt,
    ) -> ServiceResult<&AuthenticatedRequestContext> {
        let key = (
            workspace_digest.to_owned(),
            request.authority_id,
            request.sequence,
        );
        if self.requests.get(&key) != Some(request) {
            return Err(scope_required());
        }
        self.contexts
            .get(workspace_digest)
            .ok_or_else(scope_required)
    }
}

fn scope_required() -> ServiceError {
    ServiceError::new(
        ErrorCode::EvidenceRequired,
        "archive continuation requires fresh host authority for every retained scope",
        false,
    )
}

/// Exact requests derived from an admitted path, never a caller supplied scope list.
pub(crate) fn path_scope_requests(
    workspace: &str,
    request: &NativeRemovalRequestReceipt,
    path: &[crate::NativeBackupReplacementReceipt],
    proofs: &[crate::NativeBackupReplacement],
    prior: Option<&crate::NativeBackupCleanupJob>,
    scopes: &VerifiedArchiveScopes,
    budget: &mut QueryBudget,
) -> ServiceResult<Option<Vec<crate::NativeBackupScopeRequest>>> {
    if path.len() > 256 {
        return Err(exhausted("archive input ancestry exceeds 256 edges"));
    }
    let mut by_sequence = BTreeMap::new();
    for proof in proofs {
        budget
            .charge(1, 0)
            .map_err(crate::raw_index::budget_error)?;
        if by_sequence.insert(proof.receipt.sequence, proof).is_some() {
            return Err(integrity("archive scope ancestry repeats an edge sequence"));
        }
    }
    let mut required = BTreeMap::new();
    let mut add = |workspace: &str, request: &NativeRemovalRequestReceipt| -> ServiceResult<()> {
        scopes.context_for(workspace, request)?;
        let scope = crate::NativeBackupScopeRequest {
            workspace_digest: workspace.to_owned(),
            request: request.clone(),
        };
        let bytes = encode(&scope)?;
        budget
            .charge(1, bytes.len() as u64)
            .map_err(crate::raw_index::budget_error)?;
        let key = (workspace.to_owned(), request.sequence);
        if required
            .insert(key, scope.clone())
            .is_some_and(|previous| previous != scope)
        {
            return Err(integrity(
                "archive path repeats contradictory scope requests",
            ));
        }
        Ok(())
    };
    add(workspace, request)?;
    if let Some(prior) = prior {
        add(&prior.binding.workspace_digest, &prior.binding.request)?;
        if let Some(continuation) = &prior.binding.scope_continuation {
            for required in &continuation.requests {
                add(&required.workspace_digest, &required.request)?;
            }
        }
    }
    for receipt in path {
        let proof = by_sequence
            .get(&receipt.sequence)
            .filter(|proof| proof.receipt == *receipt)
            .ok_or_else(|| integrity("archive scope path lacks its exact retained edge"))?;
        add(&proof.workspace_digest, &proof.request)?;
    }
    if required.len() > 512 {
        return Err(exhausted("archive provenance exceeds 512 scope requests"));
    }
    if required
        .values()
        .all(|scope| scope.workspace_digest == workspace)
    {
        Ok(None)
    } else {
        Ok(Some(required.into_values().collect()))
    }
}
