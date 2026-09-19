//! Native assertion publication. Originals, policies, and semantics share one writer.

mod query;
#[cfg(test)]
mod tests;
mod verify;

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    AssertionStance, AuthorityPolicy, CommitSeq, ContentDigest, EventCoverage, EventKind,
    ObservationId, OriginalSourceSpan, PipelineIdentity, RevisionNumber, ScopeId, SourceAssertion,
    SourceAuthority, StateKey, Validate,
};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AssertionMutation, AssertionPort, AssertionReceipt, AuthenticatedRequestContext, Capability,
    CapturePort, ErrorCode, InterpretationDisposition, InterpretationInputs,
    PublishAssertionsRequest, ResolveStateRequest, ServiceError, ServiceResult, StateView,
};
use contextdb_storage::{
    Durability, ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine, WriteTransaction,
};
use serde::{Deserialize, Serialize};

use super::raw_index::budget_error;
use super::{
    NativeService, canonical_digest, decode, digest_bytes, encode, exhausted, integrity, invalid,
    require_capability, require_sync, storage_error,
};

pub(super) const STATE_FEATURE: &str = "continuous-assertions-v1";
const DOMAIN: &str = "contextdb.native-assertions/v1";
const MAX_WINDOW: usize = 128;
const MAX_SLOT_ROWS: usize = 512;
const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;

struct OriginalSupport<'a> {
    key: &'a StateKey,
    origin: ObservationId,
    authority: &'a SourceAuthority,
    evidence: &'a [OriginalSourceSpan],
}

struct RawWindow {
    from: u64,
    through: u64,
    limit: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Coverage {
    through: u64,
    publication: u64,
    complete_prefix: bool,
    pending: BTreeSet<ObservationId>,
    gaps: BTreeSet<ObservationId>,
}

/// This is the accepted mutation payload, not an audit hash or extracted text.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedAssertions {
    workspace_id: String,
    access: contextdb_service::AccessPolicy,
    scope: ScopeId,
    commit: u64,
    observed_scope_epoch: u64,
    request_digest: String,
    pipeline: PipelineIdentity,
    interpretations: Vec<contextdb_service::EventInterpretation>,
    mutations: Vec<AssertionMutation>,
    coverage: Coverage,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAuthority {
    commit: u64,
    access: contextdb_service::AccessPolicy,
    policy: AuthorityPolicy,
}

/// Only dependency IDs and version binding are read before source authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationLabel {
    commit: u64,
    sources: BTreeSet<ObservationId>,
    body_key: Vec<u8>,
    body_digest: String,
    envelope: Option<contextdb_core::SemanticEnvelope>,
}

impl AssertionPort for NativeService {
    fn interpretation_inputs(
        &self,
        context: &AuthenticatedRequestContext,
        scope: ScopeId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<InterpretationInputs> {
        require_scope(context, scope, Capability::Admin)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let workspace = workspace(context);
        let coverage = self.latest_coverage(&snapshot, &workspace, scope)?;
        let head = self
            .workspace_state(&snapshot, &context.request.workspace_id)?
            .watermarks
            .journal;
        let (mut events, through, more) = self.scope_raw_window(
            &snapshot,
            context,
            scope,
            RawWindow {
                from: coverage.through,
                through: head,
                limit: MAX_WINDOW.saturating_sub(coverage.pending.len()),
            },
            budget,
        )?;
        for id in coverage.pending {
            self.authorized_capture_policy(&snapshot, context, id)?;
            self.authorize_capture_dependencies(&snapshot, context, id)?;
            events.insert(id);
        }
        if events.len() > MAX_WINDOW {
            return Err(exhausted("interpretation pending window is full"));
        }
        Ok(InterpretationInputs {
            scope_epoch: self.scope_epoch(&snapshot, &workspace, scope)?,
            through,
            events: events.into_iter().collect(),
            more,
        })
    }

    fn publish_assertions(
        &self,
        mut request: PublishAssertionsRequest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AssertionReceipt> {
        require_scope(&request.context, request.scope, Capability::Admin)?;
        super::validate_identifier(&request.idempotency_key, "assertion retry key")?;
        request
            .pipeline
            .validate()
            .map_err(|_| invalid("interpretation pipeline is invalid"))?;
        if request.mutations.len() > 64
            || request.interpretations.len() > MAX_WINDOW
            || request
                .mutations
                .iter()
                .any(|change| change.key().scope != request.scope)
        {
            return Err(invalid(
                "assertion batch exceeds its scope or bounded profile",
            ));
        }
        let input = encode(&request)?;
        if input.len() > MAX_STATE_BYTES {
            return Err(exhausted("assertion batch exceeds four MiB"));
        }
        budget.charge(1, input.len() as u64).map_err(budget_error)?;
        if let Some(receipt) = &request.after_receipt {
            self.resolve_capture_receipt(&request.context, receipt)?;
        }
        let digest = canonical_digest(&(
            request.context.authorization_binding_digest()?,
            &request.scope,
            request.expected_scope_epoch,
            request.covered_through,
            &request.pipeline,
            &request.interpretations,
            &request.mutations,
            &request.after_receipt,
        ))?;
        let retry_key = canonical_digest(&(
            DOMAIN,
            &request.context.request.workspace_id,
            &request.idempotency_key,
        ))?;
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if let Some(receipt) = self.replay(&tx, retry_key.as_bytes(), "assertions", &digest)? {
            return Ok(receipt);
        }
        let workspace = workspace(&request.context);
        if self.scope_epoch(&tx, &workspace, request.scope)? != request.expected_scope_epoch {
            return Err(stale(
                "scope changed while interpreting; reread its input window",
            ));
        }
        let old = self.latest_coverage(&tx, &workspace, request.scope)?;
        let head = self
            .workspace_state(&tx, &request.context.request.workspace_id)?
            .watermarks
            .journal;
        if request.covered_through < old.through
            || request.covered_through > head
            || request
                .after_receipt
                .as_ref()
                .is_some_and(|r| r.workspace_commit > request.covered_through)
        {
            return Err(invalid(
                "interpretation coverage is outside its captured prefix",
            ));
        }
        let (mut required, _, more) = self.scope_raw_window(
            &tx,
            &request.context,
            request.scope,
            RawWindow {
                from: old.through,
                through: request.covered_through,
                limit: MAX_WINDOW,
            },
            budget,
        )?;
        if more {
            return Err(stale("interpretation raw tail exceeds one bounded window"));
        }
        required.extend(old.pending.iter().copied());
        let supplied: BTreeSet<_> = request
            .interpretations
            .iter()
            .map(|mark| mark.event_id)
            .collect();
        if supplied != required || supplied.len() != request.interpretations.len() {
            return Err(invalid(
                "interpretation must account for every source in its input window",
            ));
        }
        let frame = self.begin_frame(&tx, &request.context.request.workspace_id, true)?;
        let commit = frame.state.watermarks.journal;
        let mut coverage = Coverage {
            through: request.covered_through,
            publication: commit,
            complete_prefix: request.covered_through >= request.expected_scope_epoch,
            ..Coverage::default()
        };
        for mark in &request.interpretations {
            budget.charge(1, 0).map_err(budget_error)?;
            self.authorized_capture_policy(&tx, &request.context, mark.event_id)?;
            self.authorize_capture_dependencies(&tx, &request.context, mark.event_id)?;
            let original = self.load_captured_original(&tx, mark.event_id)?;
            let partial = original.event.coverage != EventCoverage::CompleteObservation
                || original.event.upstream_truncated;
            if partial || mark.disposition == InterpretationDisposition::Pending {
                coverage.pending.insert(mark.event_id);
            }
            if partial || self.captured_producer_incomplete(&tx, mark.event_id)? {
                coverage.gaps.insert(mark.event_id);
            }
        }
        for id in old.gaps {
            let original = self.load_captured_original(&tx, id)?;
            if original.event.coverage != EventCoverage::CompleteObservation
                || self.captured_producer_incomplete(&tx, id)?
            {
                coverage.gaps.insert(id);
            }
        }
        if coverage.pending.len() > MAX_WINDOW || coverage.gaps.len() > MAX_WINDOW {
            return Err(exhausted("unresolved scope coverage requires recovery"));
        }
        let mut policies = BTreeMap::<String, AuthorityPolicy>::new();
        let mut new_claims = BTreeMap::new();
        for mutation in &mut request.mutations {
            budget.charge(1, 0).map_err(budget_error)?;
            let slot = canonical_digest(mutation.key())?;
            match mutation {
                AssertionMutation::Policy { policy } => {
                    policy
                        .validate()
                        .map_err(|_| invalid("authority policy is invalid"))?;
                    if policies.contains_key(&slot) {
                        return Err(invalid(
                            "one policy revision per slot per batch is required",
                        ));
                    }
                    let previous =
                        self.authority_at(&tx, &workspace, &policy.key, u64::MAX, budget)?;
                    let expected = match previous {
                        Some(previous) => previous
                            .policy
                            .version
                            .checked_next()
                            .ok_or_else(|| exhausted("authority revisions exhausted"))?,
                        None => RevisionNumber::FIRST,
                    };
                    if policy.version != expected {
                        return Err(invalid("authority policy revision is not consecutive"));
                    }
                    policies.insert(slot, policy.clone());
                }
                AssertionMutation::Assert { assertion } => {
                    if assertion.claim.created_seq != CommitSeq::GENESIS
                        || assertion.revision.temporal.transaction_time.start != CommitSeq::GENESIS
                    {
                        return Err(invalid("assertion input cannot assign transaction time"));
                    }
                    assertion.claim.created_seq = CommitSeq::new(commit);
                    assertion.revision.temporal.transaction_time.start = CommitSeq::new(commit);
                    assertion
                        .validate()
                        .map_err(|_| invalid("source assertion is invalid"))?;
                    if assertion.revision.envelope.derivation.pipeline != request.pipeline {
                        return Err(invalid(
                            "assertion provenance uses another interpretation pipeline",
                        ));
                    }
                    if assertion.claim.workspace_id.to_string()
                        != request.context.request.workspace_id
                    {
                        return Err(super::permission_denied());
                    }
                    self.check_state_support(
                        &tx,
                        Some(&request.context),
                        OriginalSupport {
                            key: &assertion.key,
                            origin: assertion.originating_event,
                            authority: &assertion.source,
                            evidence: &assertion.original_evidence,
                        },
                        commit,
                        budget,
                    )?;
                    self.check_assertion_lineage(&tx, assertion)?;
                    check_interpreted(&request.interpretations, assertion.originating_event)?;
                    let policy =
                        self.policy_for_batch(&tx, &workspace, &assertion.key, &policies, budget)?;
                    if (assertion.stance == AssertionStance::Decision
                        || !assertion.revision.supersedes.is_empty())
                        && !policy.allows(&assertion.source, assertion.stance)
                    {
                        return Err(super::permission_denied());
                    }
                    if self
                        .raw_value::<AssertionMutation, _>(&tx, &claim_key(assertion.claim.id))?
                        .is_some()
                        || new_claims.contains_key(&assertion.claim.id)
                    {
                        return Err(invalid("claim identity was already accepted"));
                    }
                    for target in &assertion.revision.supersedes {
                        let previous = self.assertion_target(
                            &tx,
                            &request.context,
                            *target,
                            &new_claims,
                            budget,
                        )?;
                        if previous.key != assertion.key
                            || !policy.allows(&previous.source, previous.stance)
                            || !previous
                                .revision
                                .temporal
                                .valid_time
                                .overlaps(assertion.revision.temporal.valid_time)
                        {
                            return Err(invalid(
                                "supersession crosses authority, scope, or applicability",
                            ));
                        }
                    }
                    for (id, span) in assertion
                        .revision
                        .evidence
                        .iter()
                        .zip(&assertion.original_evidence)
                    {
                        if let Some(previous) =
                            self.raw_value::<OriginalSourceSpan, _>(&tx, &evidence_key(*id))?
                            && previous != *span
                        {
                            return Err(invalid(
                                "evidence identity was reused for another original span",
                            ));
                        }
                    }
                    new_claims.insert(assertion.claim.id, (**assertion).clone());
                }
                AssertionMutation::Retract { retraction } => {
                    if retraction.temporal.transaction_time.start != CommitSeq::GENESIS {
                        return Err(invalid("retraction input cannot assign transaction time"));
                    }
                    retraction.temporal.transaction_time.start = CommitSeq::new(commit);
                    retraction
                        .validate()
                        .map_err(|_| invalid("retraction is invalid"))?;
                    self.check_state_support(
                        &tx,
                        Some(&request.context),
                        OriginalSupport {
                            key: &retraction.key,
                            origin: retraction.originating_event,
                            authority: &retraction.source,
                            evidence: &retraction.original_evidence,
                        },
                        commit,
                        budget,
                    )?;
                    check_interpreted(&request.interpretations, retraction.originating_event)?;
                    let policy =
                        self.policy_for_batch(&tx, &workspace, &retraction.key, &policies, budget)?;
                    let target = self.assertion_target(
                        &tx,
                        &request.context,
                        retraction.target,
                        &new_claims,
                        budget,
                    )?;
                    if target.key != retraction.key
                        || !policy.allows(&retraction.source, target.stance)
                        || !target
                            .revision
                            .temporal
                            .valid_time
                            .overlaps(retraction.temporal.valid_time)
                    {
                        return Err(super::permission_denied());
                    }
                }
            }
        }
        let accepted = AcceptedAssertions {
            workspace_id: request.context.request.workspace_id.clone(),
            access: {
                let mut access = super::trusted_structured_policy(&request.context.request);
                access.scopes = BTreeSet::from([request.scope.to_string()]);
                access
            },
            scope: request.scope,
            commit,
            observed_scope_epoch: request.expected_scope_epoch,
            request_digest: digest.clone(),
            pipeline: request.pipeline,
            interpretations: request.interpretations,
            mutations: request.mutations,
            coverage,
        };
        let bytes = encode(&accepted)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(exhausted("accepted assertion payload exceeds four MiB"));
        }
        let receipt = AssertionReceipt {
            domain: DOMAIN.into(),
            database_id: self.database_id.clone(),
            workspace_commit: commit,
            mutation_digest: ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()),
        };
        self.enable_assertion_format(&mut tx)?;
        tx.put(
            &self.keyspaces.continuous,
            journal_key(&workspace, commit),
            bytes,
        )
        .map_err(storage_error)?;
        for (key, value) in accepted_rows(&accepted)? {
            budget
                .charge(0, (key.len() + value.len()) as u64)
                .map_err(budget_error)?;
            tx.put(&self.keyspaces.continuous, key, value)
                .map_err(storage_error)?;
        }
        tx.put(
            &self.keyspaces.continuous,
            super::capture::scope_key(&workspace, &accepted.scope.to_string()),
            encode(&commit)?,
        )
        .map_err(storage_error)?;
        self.finish_frame(
            &mut tx,
            &frame,
            "assertions",
            retry_key.as_bytes(),
            &digest,
            &receipt,
        )?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(receipt)
    }

    fn resolve_state(
        &self,
        request: ResolveStateRequest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<StateView> {
        self.resolve_assertion_state(request, budget)
    }
}

impl NativeService {
    fn scope_epoch<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        scope: ScopeId,
    ) -> ServiceResult<u64> {
        Ok(self
            .raw_value(
                snapshot,
                &super::capture::scope_key(workspace, &scope.to_string()),
            )?
            .unwrap_or_default())
    }

    fn latest_coverage<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        scope: ScopeId,
    ) -> ServiceResult<Coverage> {
        Ok(self
            .raw_value(snapshot, &coverage_head(workspace, scope))?
            .unwrap_or_default())
    }

    /// Maintenance windows inspect at most 128 outbox entries. No assertion query
    /// reconstructs an archive or runs an interpreter inside this operation.
    fn scope_raw_window<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        scope: ScopeId,
        window: RawWindow,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(BTreeSet<ObservationId>, u64, bool)> {
        budget.check().map_err(budget_error)?;
        let RawWindow {
            from,
            through,
            limit,
        } = window;
        if limit == 0 {
            return Ok((BTreeSet::new(), from, from < through));
        }
        let workspace = workspace(context);
        let prefix = format!("outbox/{workspace}/");
        let after = super::capture::work_key(&workspace, from);
        let page = snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: prefix.as_bytes(),
                    start_after: Some(&after),
                    max_entries: limit + 1,
                    max_bytes: 256 * 1024,
                },
            )
            .map_err(storage_error)?;
        let mut events = BTreeSet::new();
        let mut last = from;
        for (index, entry) in page.entries.into_iter().enumerate() {
            budget
                .charge(1, entry.value.len() as u64)
                .map_err(budget_error)?;
            let work: super::capture::CaptureWork = decode(&entry.value, "state capture window")?;
            if work.workspace_commit > through {
                return Ok((events, through, false));
            }
            if index == limit {
                return Ok((events, last, true));
            }
            last = work.workspace_commit;
            let policy: super::StoredObservationPolicy = decode(
                &snapshot
                    .get(
                        &self.keyspaces.observations_policy,
                        digest_bytes(work.event_id.to_string().as_bytes()).as_bytes(),
                    )
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("state source policy absent"))?,
                "state source policy",
            )?;
            if policy.access.workspace_id != context.request.workspace_id
                || !policy.access.scopes.contains(&scope.to_string())
            {
                continue;
            }
            self.authorized_capture_policy(snapshot, context, work.event_id)?;
            self.authorize_capture_dependencies(snapshot, context, work.event_id)?;
            events.insert(work.event_id);
        }
        Ok((
            events,
            if page.continuation.is_none() {
                through
            } else {
                last
            },
            page.continuation.is_some(),
        ))
    }

    fn authority_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        key: &StateKey,
        known: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<StoredAuthority>> {
        let prefix = format!("state/policy/{workspace}/{}/", canonical_digest(key)?);
        let page = snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: prefix.as_bytes(),
                    start_after: None,
                    max_entries: 65,
                    max_bytes: MAX_STATE_BYTES,
                },
            )
            .map_err(storage_error)?;
        if page.entries.len() > 64 || page.continuation.is_some() {
            return Err(exhausted("authority history exceeds the bounded profile"));
        }
        let mut latest = None;
        for entry in page.entries {
            budget
                .charge(1, entry.value.len() as u64)
                .map_err(budget_error)?;
            let policy: StoredAuthority = decode(&entry.value, "state authority")?;
            if policy.commit <= known {
                latest = Some(policy);
            }
        }
        Ok(latest)
    }

    fn policy_for_batch<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        key: &StateKey,
        policies: &BTreeMap<String, AuthorityPolicy>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AuthorityPolicy> {
        if let Some(policy) = policies.get(&canonical_digest(key)?) {
            return Ok(policy.clone());
        }
        self.authority_at(snapshot, workspace, key, u64::MAX, budget)?
            .map(|stored| stored.policy)
            .ok_or_else(|| invalid("state slot requires an explicit authority policy"))
    }

    fn assertion_target<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        id: contextdb_core::ClaimId,
        staged: &BTreeMap<contextdb_core::ClaimId, SourceAssertion>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<SourceAssertion> {
        if let Some(assertion) = staged.get(&id) {
            return Ok(assertion.clone());
        }
        let label: MutationLabel = self
            .raw_value(snapshot, &claim_label_key(id))?
            .ok_or_else(super::not_found)?;
        self.authorize_state_label(snapshot, context, &label, budget)?;
        let mutation = self.read_state_mutation(snapshot, &label, budget)?;
        match mutation {
            AssertionMutation::Assert { assertion }
                if assertion.claim.workspace_id.to_string() == context.request.workspace_id =>
            {
                Ok(*assertion)
            }
            _ => Err(super::permission_denied()),
        }
    }

    fn check_state_support<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: Option<&AuthenticatedRequestContext>,
        support: OriginalSupport<'_>,
        commit: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let OriginalSupport {
            key,
            origin,
            authority,
            evidence,
        } = support;
        for span in evidence {
            budget
                .charge(1, span.end.saturating_sub(span.start))
                .map_err(budget_error)?;
            if let Some(context) = context {
                self.authorized_capture_policy(snapshot, context, span.event_id)?;
                self.authorize_capture_dependencies(snapshot, context, span.event_id)?;
            }
            let original = self.load_captured_original(snapshot, span.event_id)?;
            if original.receipt.workspace_commit >= commit
                || !original.event.scope_ids.contains(&key.scope)
                || original.event.kind == EventKind::ModelRequested
            {
                return Err(invalid(
                    "assertion evidence crosses scope, knowledge, or independent-source boundaries",
                ));
            }
            self.source_span(snapshot, context, span, true)?;
        }
        let original = self.load_captured_original(snapshot, origin)?;
        if self.captured_authority(snapshot, &original.event)? != *authority {
            return Err(super::permission_denied());
        }
        Ok(())
    }

    fn authorize_state_label<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        label: &MutationLabel,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        for id in &label.sources {
            budget.charge(1, 0).map_err(budget_error)?;
            self.authorized_capture_policy(snapshot, context, *id)?;
            self.authorize_capture_dependencies(snapshot, context, *id)?;
        }
        Ok(())
    }

    fn check_assertion_lineage<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        assertion: &SourceAssertion,
    ) -> ServiceResult<()> {
        let evidence: BTreeSet<_> = assertion.revision.evidence.iter().copied().collect();
        let expected: BTreeSet<_> = evidence
            .into_iter()
            .map(|id| contextdb_core::LineageNode::Evidence { id })
            .collect();
        let actual: BTreeSet<_> = assertion
            .revision
            .envelope
            .derivation
            .inputs
            .iter()
            .cloned()
            .collect();
        if expected != actual || actual.len() != assertion.revision.envelope.derivation.inputs.len()
        {
            return Err(invalid(
                "assertion lineage must match its exact original evidence",
            ));
        }
        let mut families = BTreeSet::new();
        for span in &assertion.original_evidence {
            families.insert(
                self.load_captured_original(snapshot, span.event_id)?
                    .event
                    .source_id
                    .to_string(),
            );
        }
        if families != assertion.revision.source_families {
            return Err(invalid(
                "assertion source families differ from captured source identities",
            ));
        }
        Ok(())
    }

    fn read_state_mutation<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        label: &MutationLabel,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AssertionMutation> {
        let bytes = snapshot
            .get(&self.keyspaces.continuous, &label.body_key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("assertion body is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if digest_bytes(&bytes) != label.body_digest {
            return Err(integrity("assertion label and body differ"));
        }
        decode(&bytes, "accepted assertion")
    }

    fn enable_assertion_format<T: WriteTransaction>(&self, tx: &mut T) -> ServiceResult<()> {
        self.enable_capture_format(tx)?;
        let mut manifest: super::Manifest = decode(
            &tx.get(&self.keyspaces.meta, super::META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "native manifest",
        )?;
        if manifest.features.insert(STATE_FEATURE.into()) {
            manifest.checksum = super::manifest_checksum(&manifest)?;
            tx.put(
                &self.keyspaces.meta,
                super::META_MANIFEST_KEY.to_vec(),
                encode(&manifest)?,
            )
            .map_err(storage_error)?;
        }
        Ok(())
    }
}

fn accepted_rows(accepted: &AcceptedAssertions) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    let workspace = digest_bytes(accepted.workspace_id.as_bytes());
    let mut rows = BTreeMap::new();
    rows.insert(
        coverage_head(&workspace, accepted.scope),
        encode(&accepted.coverage)?,
    );
    rows.insert(
        format!(
            "{}{commit:020}",
            coverage_prefix(&workspace, accepted.scope),
            commit = accepted.commit
        )
        .into_bytes(),
        encode(&accepted.coverage)?,
    );
    for (ordinal, mutation) in accepted.mutations.iter().enumerate() {
        let slot = canonical_digest(mutation.key())?;
        if let AssertionMutation::Policy { policy } = mutation {
            rows.insert(
                format!(
                    "state/policy/{workspace}/{slot}/{:010}",
                    policy.version.get()
                )
                .into_bytes(),
                encode(&StoredAuthority {
                    commit: accepted.commit,
                    access: accepted.access.clone(),
                    policy: policy.clone(),
                })?,
            );
            continue;
        }
        let body = encode(mutation)?;
        let (body_key, evidence) = match mutation {
            AssertionMutation::Assert { assertion } => {
                (claim_key(assertion.claim.id), &assertion.original_evidence)
            }
            AssertionMutation::Retract { retraction } => (
                format!(
                    "state/retraction/{workspace}/{:020}/{ordinal:03}",
                    accepted.commit
                )
                .into_bytes(),
                &retraction.original_evidence,
            ),
            AssertionMutation::Policy { .. } => unreachable!(),
        };
        let label = MutationLabel {
            commit: accepted.commit,
            sources: evidence.iter().map(|span| span.event_id).collect(),
            body_key: body_key.clone(),
            body_digest: digest_bytes(&body),
            envelope: match mutation {
                AssertionMutation::Assert { assertion } => {
                    Some(assertion.revision.envelope.clone())
                }
                _ => None,
            },
        };
        rows.insert(body_key, body);
        rows.insert(
            format!(
                "{}{commit:020}/{ordinal:03}",
                slot_prefix(&workspace, &slot),
                commit = accepted.commit
            )
            .into_bytes(),
            encode(&label)?,
        );
        if let AssertionMutation::Assert { assertion } = mutation {
            rows.insert(claim_label_key(assertion.claim.id), encode(&label)?);
            for (id, span) in assertion
                .revision
                .evidence
                .iter()
                .zip(&assertion.original_evidence)
            {
                let value = encode(span)?;
                if let Some(previous) = rows.insert(evidence_key(*id), value.clone())
                    && previous != value
                {
                    return Err(invalid("evidence identity conflicts within the batch"));
                }
            }
        }
    }
    Ok(rows)
}

fn check_interpreted(
    marks: &[contextdb_service::EventInterpretation],
    id: ObservationId,
) -> ServiceResult<()> {
    if !marks.iter().any(|mark| {
        mark.event_id == id && mark.disposition == InterpretationDisposition::Interpreted
    }) {
        return Err(invalid(
            "semantic change requires an interpreted source in this batch",
        ));
    }
    Ok(())
}
fn require_scope(
    context: &AuthenticatedRequestContext,
    scope: ScopeId,
    capability: Capability,
) -> ServiceResult<()> {
    require_capability(context, capability)?;
    if !context.request.scopes.contains(&scope.to_string()) {
        return Err(super::permission_denied());
    }
    Ok(())
}
fn workspace(context: &AuthenticatedRequestContext) -> String {
    digest_bytes(context.request.workspace_id.as_bytes())
}
fn journal_key(workspace: &str, commit: u64) -> Vec<u8> {
    format!("state/journal/{workspace}/{commit:020}").into_bytes()
}
fn coverage_prefix(workspace: &str, scope: ScopeId) -> String {
    format!("state/coverage/{workspace}/{scope}/")
}
fn coverage_head(workspace: &str, scope: ScopeId) -> Vec<u8> {
    format!("state/coverage-head/{workspace}/{scope}").into_bytes()
}
fn slot_prefix(workspace: &str, slot: &str) -> String {
    format!("state/slot/{workspace}/{slot}/")
}
fn claim_key(id: contextdb_core::ClaimId) -> Vec<u8> {
    format!("state/claim/{id}").into_bytes()
}
fn claim_label_key(id: contextdb_core::ClaimId) -> Vec<u8> {
    format!("state/claim-label/{id}").into_bytes()
}
fn evidence_key(id: contextdb_core::EvidenceId) -> Vec<u8> {
    format!("state/evidence/{id}").into_bytes()
}
fn stale(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::IndexTooStale, message, true)
}
