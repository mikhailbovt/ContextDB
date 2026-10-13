use super::*;

impl NativeService {
    pub(crate) fn pruned_record<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        record: &str,
        revision: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<PrunedRecord>> {
        let Some(bytes) = snapshot
            .get(&self.keyspaces.continuous, &pruned_key(record, revision))
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        budget
            .charge(1, bytes.len() as u64)
            .map_err(raw_index::budget_error)?;
        if bytes.len() > MAX_PUBLICATION_BYTES {
            return Err(integrity("record pruning marker exceeds its bound"));
        }
        let publication: RecordPruningPublication = decode(&bytes, "record pruning marker")?;
        if publication.witness.record_digest != record
            || publication.witness.revision != revision
            || !self.raw_manifest(snapshot)?.features.contains(FEATURE)
        {
            return Err(integrity(
                "record pruning marker address or feature differs",
            ));
        }
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("pruned record lost its independent authority"))?;
        let witness = ledger.read_record_removal_witness(&publication.witness, budget)?;
        let policy = witness.policy();
        let workspace = digest_bytes(policy.access.workspace_id.as_bytes());
        let (_, event) =
            self.recovery_event(snapshot, &workspace, publication.workspace_commit, budget)?;
        if declaration(&event)? != Some(&publication)
            || publication.scopes != policy.access.scopes
            || snapshot
                .get(
                    &self.keyspaces.policy_history,
                    &history_key(record, revision),
                )
                .map_err(storage_error)?
                != Some(encode(policy)?)
            || snapshot
                .get(
                    &self.keyspaces.content_history,
                    &history_key(record, revision),
                )
                .map_err(storage_error)?
                .is_some()
        {
            return Err(integrity(
                "pruned record policy, body or accepted marker differs",
            ));
        }
        let mut expected = BTreeSet::new();
        for control in witness.controls() {
            let global = control
                .policy
                .transaction_to
                .unwrap_or(control.policy.transaction_from);
            let write = self.recovery_global_event(snapshot, global, budget)?;
            let (_, mapped) =
                self.recovery_event(snapshot, &workspace, write.workspace_commit, budget)?;
            let key = mutation_address(global, record, revision);
            let references: Vec<_> = write
                .accepted_records
                .iter()
                .filter(|reference| reference.key == key)
                .collect();
            if mapped != write
                || references.len() != 1
                || snapshot
                    .get(&self.keyspaces.continuous, &key)
                    .map_err(storage_error)?
                    .is_some()
            {
                return Err(integrity(
                    "pruned record has a changed mapping or resurrected mutation",
                ));
            }
            let reference = references[0];
            let bound = self
                .budgeted_record_mutation_control(
                    snapshot,
                    &write,
                    reference,
                    self.record_control_activation(snapshot)?,
                    Some(budget),
                )?
                .or(self.prepared_control_if_needed(snapshot, &write, reference, budget)?);
            if bound.as_ref() != Some(control) {
                return Err(integrity(
                    "pruned record control differs from independent witness",
                ));
            }
            control.validate_binding(&write, reference)?;
            if record_sources::writes::is_source_write(&write.operation) {
                expected.insert(global);
                let checkpoint = publication
                    .write_validations
                    .get(&global)
                    .ok_or_else(|| integrity("pruned record write validation absent"))?;
                ledger.check_record_write_validation(checkpoint, &write, budget)?;
            }
        }
        if expected != publication.write_validations.keys().copied().collect() {
            return Err(integrity("pruned record has unrelated write validations"));
        }
        Ok(Some(PrunedRecord {
            witness,
            publication,
        }))
    }

    fn prepared_control_if_needed<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &StoredEvent,
        reference: &RecordMutationRef,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<RecordControl>> {
        if reference.control_digest.is_some() {
            return Ok(None);
        }
        Ok(self
            .prepared_record_controls(snapshot, event, budget)?
            .remove(&reference.key))
    }

    pub(crate) fn verify_record_pruning<S: ReadSnapshot>(&self, snapshot: &S) -> ServiceResult<()> {
        let mut expected = BTreeMap::new();
        let mut budget = retention::audit_budget();
        for row in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: StoredEvent = decode(&row.value, "record pruning history")?;
            let Some(publication) = declaration(&event)? else {
                continue;
            };
            let record = self
                .pruned_record(
                    snapshot,
                    &publication.witness.record_digest,
                    publication.witness.revision,
                    &mut budget,
                )?
                .ok_or_else(|| integrity("accepted record pruning marker absent"))?;
            if record.publication != *publication
                || expected
                    .insert(
                        pruned_key(
                            &publication.witness.record_digest,
                            publication.witness.revision,
                        ),
                        encode(publication)?,
                    )
                    .is_some()
            {
                return Err(integrity(
                    "record pruning repeats or changes its accepted marker",
                ));
            }
        }
        let rows = snapshot
            .scan_prefix(&self.keyspaces.continuous, PREFIX)
            .map_err(storage_error)?;
        if self.raw_manifest(snapshot)?.features.contains(FEATURE) == expected.is_empty()
            || rows.len() != expected.len()
            || rows
                .iter()
                .any(|row| expected.get(&row.key) != Some(&row.value))
        {
            return Err(integrity(
                "record pruning family differs from accepted history",
            ));
        }
        Ok(())
    }
}
