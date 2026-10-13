//! Immutable scope provenance, never a stored authorization grant.

use super::*;

// The job/path verifier supplies the exact requests from actual retained edges
// and predecessor jobs. A caller's request list cannot supply those dependencies.
pub(in crate::encryption::keys) fn verify_scope_requests(
    actual: Option<&[NativeBackupScopeRequest]>,
    expected: &[NativeBackupScopeRequest],
    current_workspace: &str,
    authority: Uuid,
) -> contextdb_service::ServiceResult<()> {
    if expected.len() > 1026 || actual.is_some_and(|requests| requests.len() > 512) {
        return Err(crate::exhausted(
            "archive provenance exceeds 512 scope requests",
        ));
    }
    let mut canonical = BTreeMap::new();
    for scope in expected {
        valid_digest(&scope.workspace_digest).map_err(crate::storage_error)?;
        valid_digest(&scope.request.digest).map_err(crate::storage_error)?;
        if scope.request.authority_id != authority
            || authority.is_nil()
            || scope.request.sequence == 0
            || scope.request.roots.is_empty()
        {
            return Err(crate::integrity(
                "archive scope provenance changes request authority",
            ));
        }
        let key = (&scope.workspace_digest, scope.request.sequence);
        if let Some(previous) = canonical.insert(key, scope)
            && previous != scope
        {
            return Err(crate::integrity(
                "archive scope provenance repeats contradictory requests",
            ));
        }
    }
    if canonical.len() > 512 {
        return Err(crate::exhausted(
            "archive provenance exceeds 512 unique scope requests",
        ));
    }
    let mixed = canonical
        .values()
        .any(|scope| scope.workspace_digest != current_workspace);
    match actual {
        None if !mixed => Ok(()),
        Some(requests) if mixed && requests.iter().eq(canonical.into_values()) => Ok(()),
        _ => Err(crate::integrity(
            "archive scope provenance differs from its retained dependencies",
        )),
    }
}
