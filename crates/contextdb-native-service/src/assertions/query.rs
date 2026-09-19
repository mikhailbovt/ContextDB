//! Current authorization, logical history, and conservative scoped raw overlay.

use contextdb_core::{
    ConsentStatus, PolicyDecision, ResolvedState, SemanticEnvelope, TimestampMicros,
};
use contextdb_service::StateCoverageGap;

use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StateBinding {
    pub principal: String,
    pub key: StateKey,
    pub known_at: u64,
    pub scope_epoch: u64,
    pub authorization_epoch: u64,
    pub policy_digest: String,
    pub valid_at: TimestampMicros,
    pub valid_until: Option<TimestampMicros>,
}

impl NativeService {
    pub(super) fn resolve_assertion_state(
        &self,
        request: ResolveStateRequest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<StateView> {
        require_scope(&request.context, request.key.scope, Capability::Recall)?;
        if let Some(receipt) = &request.after_receipt {
            self.resolve_capture_receipt(&request.context, receipt)?;
            if request
                .known_at
                .is_some_and(|known| known < receipt.workspace_commit)
            {
                return Err(invalid(
                    "knowledge snapshot is below the capture receipt fence",
                ));
            }
        }
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let (_, world) = self.select_snapshot(
            &snapshot,
            &request.context.request.workspace_id,
            request.known_at,
        )?;
        let known = world.watermarks.journal;
        let workspace = workspace(&request.context);
        let scope_epoch = self.scope_epoch(&snapshot, &workspace, request.key.scope)?;
        let auth_epoch = self.raw_authorization_epoch(&snapshot, &workspace)?;
        let stored_authority = self
            .authority_at(&snapshot, &workspace, &request.key, known, budget)?
            .ok_or_else(super::super::not_found)?;
        if !super::super::policy_allows(&request.context.request, &stored_authority.access) {
            return Err(super::super::permission_denied());
        }
        if request.known_at.is_some() {
            let current = self
                .authority_at(&snapshot, &workspace, &request.key, u64::MAX, budget)?
                .ok_or_else(super::super::not_found)?;
            if !super::super::policy_allows(&request.context.request, &current.access) {
                return Err(super::super::permission_denied());
            }
        }
        let authority = stored_authority.policy;
        let coverage = self.coverage_at(&snapshot, &workspace, request.key.scope, known, budget)?;
        let mut gaps = Vec::new();
        let mut pending = BTreeSet::new();
        let raw_window = if coverage.complete_prefix && scope_epoch <= coverage.publication {
            Ok((BTreeSet::new(), known, false))
        } else {
            self.scope_raw_window(
                &snapshot,
                &request.context,
                request.key.scope,
                RawWindow {
                    from: coverage.through,
                    through: known,
                    limit: MAX_WINDOW,
                },
                budget,
            )
        };
        match raw_window {
            Ok((events, _, more)) => {
                if more {
                    return Err(stale("state raw overlay exceeds its bounded window"));
                }
                pending.extend(events);
            }
            Err(error) if unavailable(&error) => gaps.push(StateCoverageGap::SupportUnavailable),
            Err(error) => return Err(error),
        }
        for id in &coverage.pending {
            match self
                .authorized_capture_policy(&snapshot, &request.context, *id)
                .and_then(|_| self.authorize_capture_dependencies(&snapshot, &request.context, *id))
            {
                Ok(()) => {
                    pending.insert(*id);
                }
                Err(error) if unavailable(&error) => {
                    if !gaps.contains(&StateCoverageGap::SupportUnavailable) {
                        gaps.push(StateCoverageGap::SupportUnavailable);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        if !pending.is_empty() {
            gaps.push(StateCoverageGap::PendingInterpretation);
        }
        if !coverage.gaps.is_empty() {
            gaps.push(StateCoverageGap::CaptureGap);
        }
        let prefix = slot_prefix(&workspace, &canonical_digest(&request.key)?);
        let page = snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: prefix.as_bytes(),
                    start_after: None,
                    max_entries: MAX_SLOT_ROWS + 1,
                    max_bytes: MAX_STATE_BYTES,
                },
            )
            .map_err(storage_error)?;
        if page.entries.len() > MAX_SLOT_ROWS || page.continuation.is_some() {
            return Err(exhausted("state slot history exceeds its bounded profile"));
        }
        let mut assertions = Vec::new();
        let mut retractions = Vec::new();
        let now = wall_time()?;
        for entry in page.entries {
            budget
                .charge(1, entry.value.len() as u64)
                .map_err(budget_error)?;
            let label: MutationLabel = decode(&entry.value, "state mutation label")?;
            if label.commit > known {
                break;
            }
            match self.authorize_state_label(&snapshot, &request.context, &label, budget) {
                Ok(()) => {}
                Err(error) if unavailable(&error) => {
                    if !gaps.contains(&StateCoverageGap::SupportUnavailable) {
                        gaps.push(StateCoverageGap::SupportUnavailable);
                    }
                    continue;
                }
                Err(error) => return Err(error),
            }
            if label
                .envelope
                .as_ref()
                .is_some_and(|envelope| !envelope_allows(&request.context, envelope, now))
            {
                if !gaps.contains(&StateCoverageGap::SupportUnavailable) {
                    gaps.push(StateCoverageGap::SupportUnavailable);
                }
                continue;
            }
            match self.read_state_mutation(&snapshot, &label, budget)? {
                AssertionMutation::Assert { assertion } => assertions.push(*assertion),
                AssertionMutation::Retract { retraction } => retractions.push(retraction),
                AssertionMutation::Policy { .. } => {
                    return Err(integrity("policy appeared in an assertion route"));
                }
            }
        }
        let mut resolution = contextdb_core::resolve_assertions(
            &authority,
            &assertions,
            &retractions,
            CommitSeq::new(known),
            request.valid_at,
            gaps.is_empty(),
        )
        .map_err(|_| integrity("accepted assertion resolution is invalid"))?;
        for end in assertions
            .iter()
            .flat_map(|assertion| &assertion.revision.envelope.consent.decisions)
            .filter_map(|consent| consent.valid_time.end)
            .filter(|end| *end > now)
        {
            resolution.valid_until = Some(
                resolution
                    .valid_until
                    .map_or(end, |previous| previous.min(end)),
            );
        }
        // An absent/denied negative transition must never make old support current.
        if !gaps.is_empty() {
            resolution.state = ResolvedState::Incomplete;
        }
        let binding = StateBinding {
            principal: request.context.authorization_binding_digest()?,
            key: request.key.clone(),
            known_at: known,
            scope_epoch,
            authorization_epoch: auth_epoch,
            policy_digest: canonical_digest(&authority)?,
            valid_at: request.valid_at,
            valid_until: resolution.valid_until,
        };
        let latest = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if self.raw_authorization_epoch(&latest, &workspace)? != auth_epoch
            || self.scope_epoch(&latest, &workspace, request.key.scope)? != scope_epoch
        {
            return Err(stale("state or permissions changed during resolution"));
        }
        budget.check().map_err(budget_error)?;
        Ok(StateView {
            resolution,
            authority,
            assertions,
            retractions,
            coverage_gaps: gaps,
            pending_events: pending.into_iter().collect(),
            binding: self.seal_private_cursor(b"contextdb/state-view/v1", &binding)?,
        })
    }

    fn coverage_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        scope: ScopeId,
        known: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Coverage> {
        let head = self.latest_coverage(snapshot, workspace, scope)?;
        if head.publication <= known {
            return Ok(head);
        }
        let prefix = coverage_prefix(workspace, scope);
        let page = snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: prefix.as_bytes(),
                    start_after: None,
                    max_entries: MAX_SLOT_ROWS + 1,
                    max_bytes: MAX_STATE_BYTES,
                },
            )
            .map_err(storage_error)?;
        if page.entries.len() > MAX_SLOT_ROWS || page.continuation.is_some() {
            return Err(exhausted(
                "historical interpretation coverage exceeds its bounded profile",
            ));
        }
        let mut latest = Coverage::default();
        for entry in page.entries {
            budget
                .charge(1, entry.value.len() as u64)
                .map_err(budget_error)?;
            let value: Coverage = decode(&entry.value, "interpretation coverage")?;
            if value.publication > known {
                break;
            }
            latest = value;
        }
        Ok(latest)
    }
}

fn unavailable(error: &ServiceError) -> bool {
    matches!(
        error.code,
        ErrorCode::NotFound | ErrorCode::PermissionDenied | ErrorCode::EvidenceRequired
    )
}

fn wall_time() -> ServiceResult<TimestampMicros> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| stale("wall clock is unavailable"))?;
    Ok(TimestampMicros(
        i64::try_from(duration.as_micros()).map_err(|_| exhausted("wall clock overflow"))?,
    ))
}

/// The semantic envelope can narrow original access, never broaden it. Consent
/// uses current wall time even for a historical valid-time query.
fn envelope_allows(
    context: &AuthenticatedRequestContext,
    envelope: &SemanticEnvelope,
    now: TimestampMicros,
) -> bool {
    use contextdb_core::{AccessCapability, Audience, Purpose, SecurityClassification};
    let request = &context.request;
    let purpose = |value: &Purpose| match value {
        Purpose::UserSpecified(value) => value.clone(),
        value => contextdb_recall::purpose_key(value),
    };
    let clearance = match request.clearance {
        contextdb_service::Sensitivity::Public => SecurityClassification::Public,
        contextdb_service::Sensitivity::Internal => SecurityClassification::Internal,
        contextdb_service::Sensitivity::Private => SecurityClassification::Confidential,
        contextdb_service::Sensitivity::Restricted => SecurityClassification::Restricted,
    };
    if envelope.use_policy.retrieve != PolicyDecision::Allow
        || envelope.security.classification > clearance
        || !envelope
            .security
            .required_compartments
            .iter()
            .all(|scope| request.scopes.contains(&scope.to_string()))
        || !envelope
            .ownership
            .allowed_purposes
            .iter()
            .any(|value| purpose(value) == request.purpose)
        || (envelope.consent.required
            && (envelope.consent.decisions.is_empty()
                || envelope.consent.decisions.iter().any(|consent| {
                    consent.status != ConsentStatus::Granted || !consent.valid_time.contains(now)
                })))
    {
        return false;
    }
    if envelope
        .ownership
        .owners
        .iter()
        .any(|owner| owner.to_string() == request.subject_id)
    {
        return true;
    }
    envelope.ownership.audience_grants.iter().any(|grant| {
        let audience = match &grant.audience {
            Audience::Subject { id } => id.to_string() == request.subject_id,
            Audience::Public => true,
            _ => false,
        };
        audience
            && grant.capabilities.contains(&AccessCapability::Retrieve)
            && grant
                .purposes
                .iter()
                .any(|value| purpose(value) == request.purpose)
    })
}
