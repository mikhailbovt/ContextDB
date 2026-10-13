//! Administrative journal replay; never used by the interactive resolver.

use super::retention::{
    RemovedKind, RemovedMutation, RetainedAssertions, RetainedMutation, retained_rows,
};
use super::*;

impl NativeService {
    pub(in super::super) fn verify_assertion_records<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<()> {
        self.verify_assertion_records_budget(snapshot, &mut crate::retention::audit_budget())
            .map(|_| ())
    }

    pub(crate) fn verify_assertion_records_budget<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeSet<ObservationId>> {
        let manifest: super::super::Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, super::super::META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "native manifest",
        )?;
        let mut expected = BTreeMap::new();
        let mut policies = BTreeMap::<(String, String), AuthorityPolicy>::new();
        let mut claims = BTreeMap::new();
        let mut live_sources = BTreeSet::new();
        let mut coverage = BTreeMap::<(String, ScopeId), Coverage>::new();
        let mut bindings = self.assertion_pruning_bindings(snapshot, budget)?;
        for entry in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let journal: super::super::StoredEvent =
                decode(&entry.value, "assertion journal reference")?;
            let Some(receipt) = &journal.accepted_assertions else {
                if journal.operation == "assertions" {
                    return Err(integrity(
                        "semantic journal lost its accepted payload reference",
                    ));
                }
                continue;
            };
            if journal.operation != "assertions"
                || !manifest.features.contains(STATE_FEATURE)
                || receipt.domain != DOMAIN
                || receipt.database_id != self.database_id
                || receipt.workspace_commit != journal.workspace_commit
                || digest_bytes(&encode(receipt)?) != journal.response_digest
            {
                return Err(integrity(
                    "assertion journal domain or receipt binding is invalid",
                ));
            }
            let binding =
                bindings.remove(&(journal.workspace_digest.clone(), journal.workspace_commit));
            let (key, bytes, batch) =
                self.load_retained_assertions(snapshot, &journal, binding.as_ref(), budget)?;
            let accepted = &batch.control;
            if accepted.commit != journal.workspace_commit
                || accepted.request_digest != journal.request_digest
                || accepted.access.workspace_id != accepted.workspace_id
                || accepted.access.scopes != BTreeSet::from([accepted.scope.to_string()])
                || digest_bytes(accepted.workspace_id.as_bytes()) != journal.workspace_digest
                || accepted.coverage.publication != accepted.commit
                || accepted.coverage.through >= accepted.commit
                || accepted.coverage.complete_prefix
                    != (accepted.coverage.through >= accepted.observed_scope_epoch)
                || accepted.coverage.pending.len() > MAX_WINDOW
                || accepted.coverage.gaps.len() > MAX_WINDOW
                || accepted.mutations.len() > 64
                || accepted.interpretations.len() > MAX_WINDOW
            {
                return Err(integrity("accepted semantic publication fields differ"));
            }
            let coverage_key = (accepted.workspace_id.clone(), accepted.scope);
            let previous = coverage.entry(coverage_key).or_default();
            if accepted.coverage.through < previous.through {
                return Err(integrity("interpretation coverage regressed"));
            }
            let mut required = previous.pending.clone();
            let prefix = format!("outbox/{}/", journal.workspace_digest);
            let after =
                super::super::capture::work_key(&journal.workspace_digest, previous.through);
            let window = snapshot
                .scan_prefix_page(
                    &self.keyspaces.continuous,
                    ScanPageRequest {
                        prefix: prefix.as_bytes(),
                        start_after: Some(&after),
                        max_entries: MAX_WINDOW + 1,
                        max_bytes: 256 * 1024,
                    },
                )
                .map_err(storage_error)?;
            for (index, entry) in window.entries.iter().enumerate() {
                let work: super::super::capture::CaptureWork =
                    decode(&entry.value, "accepted input window")?;
                if work.workspace_commit > accepted.coverage.through {
                    break;
                }
                if index == MAX_WINDOW {
                    return Err(integrity("accepted input window exceeded its bound"));
                }
                let original = self.verified_capture_control(snapshot, work.event_id, budget)?;
                if original.recovery.scope_ids.contains(&accepted.scope)
                    && self.capture_affects_scope(snapshot, work.event_id)?
                {
                    required.insert(work.event_id);
                }
            }
            let supplied: BTreeSet<_> = accepted
                .interpretations
                .iter()
                .map(|mark| mark.event_id)
                .collect();
            if supplied != required || supplied.len() != accepted.interpretations.len() {
                return Err(integrity("accepted semantic coverage omits a raw source"));
            }
            let mut pending = BTreeSet::new();
            for mark in &accepted.interpretations {
                let original = self.verified_capture_control(snapshot, mark.event_id, budget)?;
                if mark.disposition == InterpretationDisposition::Pending
                    || original.recovery.coverage != EventCoverage::CompleteObservation
                    || original.recovery.upstream_truncated
                {
                    pending.insert(mark.event_id);
                }
            }
            if pending != accepted.coverage.pending {
                return Err(integrity(
                    "accepted interpretation status and coverage differ",
                ));
            }
            *previous = accepted.coverage.clone();
            for retained in &batch.mutations {
                let control = match retained {
                    RetainedMutation::Removed { control, .. } => control.clone(),
                    RetainedMutation::Live { mutation } => {
                        let slot = (
                            accepted.workspace_id.clone(),
                            canonical_digest(mutation.key())?,
                        );
                        match mutation {
                            AssertionMutation::Policy { policy } => {
                                policy
                                    .validate()
                                    .map_err(|_| integrity("accepted authority policy invalid"))?;
                                let version = policies
                                    .get(&slot)
                                    .map_or(Some(RevisionNumber::FIRST), |previous| {
                                        previous.version.checked_next()
                                    });
                                if Some(policy.version) != version {
                                    return Err(integrity(
                                        "accepted authority versions are not consecutive",
                                    ));
                                }
                                policies.insert(slot, policy.clone());
                                continue;
                            }
                            AssertionMutation::Assert { assertion } => {
                                assertion.validate().map_err(|_| {
                                    integrity("accepted canonical assertion invalid")
                                })?;
                                self.check_assertion_lineage(snapshot, assertion)?;
                                if canonical_digest(
                                    &assertion.revision.envelope.derivation.pipeline,
                                )? != accepted.pipeline_digest
                                    || assertion.claim.workspace_id.to_string()
                                        != accepted.workspace_id
                                    || assertion.claim.created_seq.get() != accepted.commit
                                {
                                    return Err(integrity(
                                        "assertion interpreter or commit domain differs",
                                    ));
                                }
                                self.check_state_support(
                                    snapshot,
                                    None,
                                    OriginalSupport {
                                        key: &assertion.key,
                                        origin: assertion.originating_event,
                                        authority: &assertion.source,
                                        evidence: &assertion.original_evidence,
                                    },
                                    accepted.commit,
                                    budget,
                                )
                                .map_err(|_| {
                                    integrity("assertion original evidence binding is invalid")
                                })?;
                            }
                            AssertionMutation::Retract { retraction } => {
                                retraction
                                    .validate()
                                    .map_err(|_| integrity("accepted retraction invalid"))?;
                                if retraction.temporal.transaction_time.start.get()
                                    != accepted.commit
                                {
                                    return Err(integrity("accepted retraction commit differs"));
                                }
                                self.check_state_support(
                                    snapshot,
                                    None,
                                    OriginalSupport {
                                        key: &retraction.key,
                                        origin: retraction.originating_event,
                                        authority: &retraction.source,
                                        evidence: &retraction.original_evidence,
                                    },
                                    accepted.commit,
                                    budget,
                                )
                                .map_err(|_| integrity("retraction evidence binding invalid"))?;
                            }
                        }
                        let control = RemovedMutation::from_mutation(mutation)?;
                        live_sources.extend(control.sources.iter().copied());
                        control
                    }
                };
                check_interpreted(&accepted.interpretations, control.origin)
                    .map_err(|_| integrity("assertion source was not interpreted"))?;
                let slot = (
                    accepted.workspace_id.clone(),
                    canonical_digest(&control.key)?,
                );
                let policy = policies
                    .get(&slot)
                    .ok_or_else(|| integrity("accepted assertion authority absent"))?;
                match &control.kind {
                    RemovedKind::Assert {
                        claim,
                        stance,
                        supersedes,
                    } => {
                        if (*stance == AssertionStance::Decision || !supersedes.is_empty())
                            && !allows_digest(policy, &control.source_digest, *stance)?
                        {
                            return Err(integrity("accepted assertion exceeds source authority"));
                        }
                        for id in supersedes {
                            let target: &RemovedMutation = claims
                                .get(id)
                                .ok_or_else(|| integrity("superseded claim absent"))?;
                            let RemovedKind::Assert { stance, .. } = target.kind else {
                                unreachable!()
                            };
                            if target.key != control.key
                                || !allows_digest(policy, &target.source_digest, stance)?
                                || !target.valid_time.overlaps(control.valid_time)
                            {
                                return Err(integrity(
                                    "accepted supersession crosses scope or time",
                                ));
                            }
                        }
                        if claims.insert(*claim, control.clone()).is_some() {
                            return Err(integrity("canonical claim identity was reused"));
                        }
                    }
                    RemovedKind::Retract { target } => {
                        let target: &RemovedMutation = claims
                            .get(target)
                            .ok_or_else(|| integrity("retracted claim absent"))?;
                        let RemovedKind::Assert { stance, .. } = target.kind else {
                            unreachable!()
                        };
                        if target.key != control.key
                            || !allows_digest(policy, &control.source_digest, stance)?
                            || !target.valid_time.overlaps(control.valid_time)
                        {
                            return Err(integrity("accepted retraction exceeds authority"));
                        }
                    }
                }
            }
            expected.insert(key, bytes);
            for (key, value) in retained_rows(&batch)? {
                if key.starts_with(b"state/evidence/")
                    && expected
                        .get(&key)
                        .is_some_and(|previous| previous != &value)
                {
                    return Err(integrity("accepted evidence identity changed"));
                }
                expected.insert(key, value);
            }
        }
        if !bindings.is_empty() {
            return Err(integrity(
                "assertion pruning has no original accepted batch",
            ));
        }
        let actual = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"state/")
            .map_err(storage_error)?;
        if actual.len() != expected.len()
            || actual
                .iter()
                .any(|entry| expected.get(&entry.key) != Some(&entry.value))
        {
            return Err(integrity(
                "assertion projections differ from accepted semantic payloads",
            ));
        }
        self.verify_state_catalog(snapshot, budget)?;
        Ok(live_sources)
    }

    pub(in super::super) fn assertion_scope_epochs<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<BTreeMap<Vec<u8>, u64>> {
        let mut epochs = BTreeMap::<Vec<u8>, u64>::new();
        for (prefix, pruned) in [
            (b"state/journal/".as_slice(), false),
            (b"state/pruned-journal/".as_slice(), true),
        ] {
            for entry in snapshot
                .scan_prefix(&self.keyspaces.continuous, prefix)
                .map_err(storage_error)?
            {
                let (workspace, scope, commit) = if pruned {
                    let batch: RetainedAssertions =
                        decode(&entry.value, "pruned assertion scope publication")?;
                    (
                        batch.control.workspace_id,
                        batch.control.scope,
                        batch.control.commit,
                    )
                } else {
                    let accepted: AcceptedAssertions =
                        decode(&entry.value, "assertion scope publication")?;
                    (accepted.workspace_id, accepted.scope, accepted.commit)
                };
                let key = crate::capture::scope_key(
                    &digest_bytes(workspace.as_bytes()),
                    &scope.to_string(),
                );
                let previous = epochs.entry(key).or_default();
                *previous = (*previous).max(commit);
            }
        }
        Ok(epochs)
    }
}

fn allows_digest(
    policy: &AuthorityPolicy,
    source: &str,
    stance: AssertionStance,
) -> ServiceResult<bool> {
    for grant in &policy.grants {
        if grant.stance == stance && canonical_digest(&grant.source)? == source {
            return Ok(true);
        }
    }
    Ok(false)
}
