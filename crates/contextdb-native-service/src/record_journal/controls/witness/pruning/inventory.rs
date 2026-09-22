//! Prove that primary source deletion leaves no affected generic body copies.

use super::*;

impl NativeService {
    pub(crate) fn require_record_copies_pruned<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        sources: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("generic copy inventory requires retained authority"))?;
        let world = self.recovery_workspace(snapshot, workspace, budget)?;
        let mut policies = BTreeMap::new();
        let mut expected = BTreeMap::new();
        let mut bodies = BTreeSet::new();
        let mut after = None;
        loop {
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.policy_history,
                    ScanPageRequest {
                        prefix: b"",
                        start_after: after.as_deref(),
                        max_entries: 256,
                        max_bytes: 1024 * 1024,
                    },
                )
                .map_err(storage_error)?;
            for row in page.entries {
                budget
                    .charge(1, row.value.len() as u64)
                    .map_err(raw_index::budget_error)?;
                let policy: StoredPolicy = decode(&row.value, "generic copy inventory policy")?;
                validate_stored_policy(&policy)?;
                if row.key != history_key(&policy.record_digest, policy.revision) {
                    return Err(integrity("generic copy inventory policy identity differs"));
                }
                after = Some(row.key.clone());
                let record_workspace = digest_bytes(policy.access.workspace_id.as_bytes());
                policies.insert(row.key, record_workspace.clone());
                if record_workspace != workspace {
                    continue;
                }
                let binding = ledger
                    .retained_record_sources(workspace, &policy.record_digest, policy.revision)?
                    .ok_or_else(|| {
                        ServiceError::new(
                            ErrorCode::EvidenceRequired,
                            "classify every generic revision before primary source removal",
                            false,
                        )
                    })?;
                let origin = binding.record_control()?;
                budget
                    .charge(1, encode(origin)?.len() as u64)
                    .map_err(raw_index::budget_error)?;
                self.verify_local_record_origin(snapshot, origin, budget)?;
                let pruned =
                    self.pruned_record(snapshot, &policy.record_digest, policy.revision, budget)?;
                if origin.sources.keys().any(|id| sources.contains(id)) && pruned.is_none() {
                    return Err(unsupported(
                        "prune source-supported generic revisions before primary originals",
                    ));
                }
                for (global, digest) in
                    std::iter::once((policy.transaction_from, &origin.birth_digest)).chain(
                        policy
                            .transaction_to
                            .map(|global| (global, &policy.content_digest)),
                    )
                {
                    let key = mutation_address(global, &policy.record_digest, policy.revision);
                    expected.insert(key.clone(), digest.clone());
                    if pruned.is_none() {
                        bodies.insert(key);
                    }
                }
            }
            if page.continuation.is_none() {
                break;
            }
        }
        let activated: Option<u64> = self.raw_value(snapshot, record_journal::ACTIVATED)?;
        for commit in 1..=world.watermarks.journal {
            let (_, event) = self.recovery_event(snapshot, workspace, commit, budget)?;
            if (!event.accepted_records.is_empty()
                && (!owns_record_mutations(&event.operation)
                    || activated.is_none_or(|first| first > event.global_commit)))
                || (owns_record_mutations(&event.operation)
                    && activated.is_some_and(|first| first <= event.global_commit)
                    && event.accepted_records.is_empty())
                || event.accepted_records.len() > MAX_WRITES
            {
                return Err(integrity(
                    "generic copy inventory has invalid journal ownership",
                ));
            }
            for reference in &event.accepted_records {
                if expected.remove(&reference.key).as_ref() != Some(&reference.digest) {
                    return Err(integrity(
                        "accepted generic copy differs from revision inventory",
                    ));
                }
                if bodies.contains(&reference.key) {
                    let bytes = read_bytes(
                        snapshot,
                        &self.keyspaces.continuous,
                        &reference.key,
                        MAX_BYTES,
                        budget,
                    )?;
                    if digest_bytes(&bytes) != reference.digest {
                        return Err(integrity(
                            "independent generic copy differs from accepted bytes",
                        ));
                    }
                    let record: MemoryRecord = decode(&bytes, "independent generic mutation")?;
                    RecordControl::from_record(&record)?.validate_binding(&event, reference)?;
                }
            }
        }
        if !expected.is_empty() {
            return Err(integrity(
                "generic revision lost an accepted birth or closure",
            ));
        }
        // Reverse closure includes historical bodies and catches orphaned copies
        // even when their policy or entire accepted group was removed.
        for (space, prefix) in [
            (&self.keyspaces.content_history, b"".as_slice()),
            (&self.keyspaces.continuous, b"semantic/record/".as_slice()),
        ] {
            let mut after = None;
            loop {
                let page = snapshot
                    .scan_prefix_page(
                        space,
                        ScanPageRequest {
                            prefix,
                            start_after: after.as_deref(),
                            max_entries: 256,
                            max_bytes: MAX_BYTES,
                        },
                    )
                    .map_err(storage_error)?;
                for row in page.entries {
                    budget
                        .charge(1, row.value.len() as u64)
                        .map_err(raw_index::budget_error)?;
                    let record = if prefix.is_empty() {
                        decode::<StoredContent>(&row.value, "generic copy inventory content")?
                            .record
                    } else {
                        decode::<MemoryRecord>(&row.value, "generic copy inventory mutation")?
                    };
                    let record_workspace =
                        digest_bytes(record.document.access.workspace_id.as_bytes());
                    let policy_key = history_key(
                        &digest_bytes(record.document.id.as_bytes()),
                        record.revision,
                    );
                    let expected_key = if prefix.is_empty() {
                        policy_key.clone()
                    } else {
                        mutation_address(
                            record.transaction_to.unwrap_or(record.transaction_from),
                            &digest_bytes(record.document.id.as_bytes()),
                            record.revision,
                        )
                    };
                    if row.key != expected_key
                        || policies.get(&policy_key) != Some(&record_workspace)
                    {
                        return Err(integrity(
                            "generic body has no matching policy inventory entry",
                        ));
                    }
                    if !prefix.is_empty()
                        && record_workspace == workspace
                        && !bodies.remove(&row.key)
                    {
                        return Err(integrity("generic copy has no accepted inventory entry"));
                    }
                    after = Some(row.key);
                }
                if page.continuation.is_none() {
                    break;
                }
            }
        }
        if !bodies.is_empty() {
            return Err(integrity("generic copy inventory lost retained bodies"));
        }
        Ok(())
    }
}
