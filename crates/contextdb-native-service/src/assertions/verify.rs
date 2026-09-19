//! Administrative journal replay; never used by the interactive resolver.

use super::*;

impl NativeService {
    pub(in super::super) fn verify_assertion_records<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<()> {
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
        let mut coverage = BTreeMap::<(String, ScopeId), Coverage>::new();
        let mut budget = QueryBudget::new(
            u64::MAX,
            u64::MAX,
            std::time::Duration::from_secs(3600),
            Default::default(),
        );
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
            let key = journal_key(&journal.workspace_digest, journal.workspace_commit);
            let bytes = snapshot
                .get(&self.keyspaces.continuous, &key)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("accepted semantic payload is absent"))?;
            if ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes())
                != receipt.mutation_digest
            {
                return Err(integrity("accepted semantic payload digest differs"));
            }
            let accepted: AcceptedAssertions = decode(&bytes, "accepted semantic payload")?;
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
                || accepted
                    .mutations
                    .iter()
                    .any(|mutation| mutation.key().scope != accepted.scope)
            {
                return Err(integrity("accepted semantic publication fields differ"));
            }
            accepted
                .pipeline
                .validate()
                .map_err(|_| integrity("accepted interpreter identity invalid"))?;
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
                let original = self.load_captured_original(snapshot, work.event_id)?;
                if original.event.scope_ids.contains(&accepted.scope) {
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
                let original = self.load_captured_original(snapshot, mark.event_id)?;
                if mark.disposition == InterpretationDisposition::Pending
                    || original.event.coverage != EventCoverage::CompleteObservation
                    || original.event.upstream_truncated
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
            for mutation in &accepted.mutations {
                let slot = (
                    accepted.workspace_id.clone(),
                    canonical_digest(mutation.key())?,
                );
                match mutation {
                    AssertionMutation::Policy { policy } => {
                        policy
                            .validate()
                            .map_err(|_| integrity("accepted authority policy invalid"))?;
                        let expected_version = policies
                            .get(&slot)
                            .map_or(Some(RevisionNumber::FIRST), |previous| {
                                previous.version.checked_next()
                            });
                        if Some(policy.version) != expected_version {
                            return Err(integrity(
                                "accepted authority versions are not consecutive",
                            ));
                        }
                        policies.insert(slot, policy.clone());
                    }
                    AssertionMutation::Assert { assertion } => {
                        assertion
                            .validate()
                            .map_err(|_| integrity("accepted canonical assertion invalid"))?;
                        self.check_assertion_lineage(snapshot, assertion)
                            .map_err(|_| {
                                integrity(
                                    "accepted assertion lineage differs from its original support",
                                )
                            })?;
                        if assertion.revision.envelope.derivation.pipeline != accepted.pipeline {
                            return Err(integrity("assertion interpreter provenance differs"));
                        }
                        if assertion.claim.workspace_id.to_string() != accepted.workspace_id
                            || assertion.claim.created_seq.get() != accepted.commit
                        {
                            return Err(integrity("assertion commit domain differs"));
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
                            &mut budget,
                        )
                        .map_err(|_| integrity("assertion original evidence binding is invalid"))?;
                        check_interpreted(&accepted.interpretations, assertion.originating_event)
                            .map_err(|_| integrity("assertion source was not interpreted"))?;
                        let policy = policies.get(&slot).ok_or_else(|| {
                            integrity("accepted assertion has no authority policy")
                        })?;
                        if (assertion.stance == AssertionStance::Decision
                            || !assertion.revision.supersedes.is_empty())
                            && !policy.allows(&assertion.source, assertion.stance)
                        {
                            return Err(integrity("accepted assertion exceeds source authority"));
                        }
                        for id in &assertion.revision.supersedes {
                            let target: &SourceAssertion = claims
                                .get(id)
                                .ok_or_else(|| integrity("superseded claim is absent"))?;
                            if target.key != assertion.key
                                || !policy.allows(&target.source, target.stance)
                                || !target
                                    .revision
                                    .temporal
                                    .valid_time
                                    .overlaps(assertion.revision.temporal.valid_time)
                            {
                                return Err(integrity(
                                    "accepted supersession crosses scope or time",
                                ));
                            }
                        }
                        if claims
                            .insert(assertion.claim.id, (**assertion).clone())
                            .is_some()
                        {
                            return Err(integrity("canonical claim identity was reused"));
                        }
                    }
                    AssertionMutation::Retract { retraction } => {
                        retraction
                            .validate()
                            .map_err(|_| integrity("accepted retraction invalid"))?;
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
                            &mut budget,
                        )
                        .map_err(|_| integrity("retraction evidence binding invalid"))?;
                        check_interpreted(&accepted.interpretations, retraction.originating_event)
                            .map_err(|_| integrity("retraction source not interpreted"))?;
                        let target = claims
                            .get(&retraction.target)
                            .ok_or_else(|| integrity("retracted claim absent"))?;
                        let policy = policies
                            .get(&slot)
                            .ok_or_else(|| integrity("retraction authority absent"))?;
                        if retraction.temporal.transaction_time.start.get() != accepted.commit
                            || target.key != retraction.key
                            || !policy.allows(&retraction.source, target.stance)
                            || !target
                                .revision
                                .temporal
                                .valid_time
                                .overlaps(retraction.temporal.valid_time)
                        {
                            return Err(integrity("accepted retraction exceeds authority"));
                        }
                    }
                }
            }
            expected.insert(key, bytes);
            for (key, value) in accepted_rows(&accepted)? {
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
        Ok(())
    }

    pub(in super::super) fn assertion_scope_epochs<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<BTreeMap<Vec<u8>, u64>> {
        let mut epochs = BTreeMap::<Vec<u8>, u64>::new();
        for entry in snapshot
            .scan_prefix(&self.keyspaces.continuous, b"state/journal/")
            .map_err(storage_error)?
        {
            let accepted: AcceptedAssertions = decode(&entry.value, "assertion scope publication")?;
            let key = super::super::capture::scope_key(
                &digest_bytes(accepted.workspace_id.as_bytes()),
                &accepted.scope.to_string(),
            );
            let previous = epochs.entry(key).or_default();
            *previous = (*previous).max(accepted.commit);
        }
        Ok(epochs)
    }
}
