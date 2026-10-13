use super::*;

impl NativeService {
    pub(super) fn record_write_intent<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &StoredEvent,
    ) -> ServiceResult<RecordWriteIntent> {
        self.budgeted_record_write_intent(snapshot, event, &mut None)
    }

    pub(super) fn budgeted_record_write_intent<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &StoredEvent,
        budget: &mut Option<&mut QueryBudget>,
    ) -> ServiceResult<RecordWriteIntent> {
        let reference = event
            .accepted_record_write
            .as_ref()
            .ok_or_else(|| integrity("accepted source intent absent"))?;
        let bytes = control_bytes(
            snapshot,
            &self.keyspaces.continuous,
            &intent_key(event.global_commit),
            MAX_INTENT_BYTES,
            budget,
        )?
        .ok_or_else(|| integrity("accepted source intent bytes absent"))?;
        let intent: RecordWriteIntent = decode(&bytes, "accepted source intent")?;
        if !is_source_write(&event.operation)
            || event.event_digest != event_digest(event)?
            || reference.digest != digest_bytes(&bytes)
            || bytes.len() > MAX_INTENT_BYTES
            || intent.global_commit != event.global_commit
            || intent.workspace != event.workspace_digest
            || intent.request_digest != event.request_digest
            || intent.records != event.accepted_records
            || intent.records.is_empty()
            || intent.records.len() > record_journal::MAX_WRITES
            || intent.origins.is_empty()
            || intent.origins.len() > intent.records.len()
            || (event.operation == PUBLISH
                && (intent.records.len() != 1
                    || intent.origins.len() != 1
                    || intent.group.is_some()))
            || (event.operation != PUBLISH && intent.group.is_none())
            || ((event.operation == CORRECT)
                != intent
                    .group
                    .as_ref()
                    .is_some_and(|group| group.is_correction()))
            || std::str::from_utf8(&intent.idempotency_key)
                .ok()
                .is_none_or(|key| blake3::Hash::from_hex(key).is_err())
        {
            return Err(integrity("accepted source intent differs from its journal"));
        }
        for control in &intent.origins {
            control
                .validate()
                .map_err(|_| integrity("accepted source control is invalid"))?;
        }
        let receipt: StoredIdempotency = decode(
            &control_bytes(
                snapshot,
                &self.keyspaces.idempotency,
                &intent.idempotency_key,
                MAX_JSON_BYTES,
                budget,
            )?
            .ok_or_else(|| integrity("source-aware write retry receipt absent"))?,
            "source-aware write retry receipt",
        )?;
        let response: MutationResponse = if event.operation == PROPOSE {
            let proposal: ProposeMemoryResponse =
                decode(&receipt.response_bytes, "source-aware proposal response")?;
            intent
                .group
                .as_ref()
                .ok_or_else(|| integrity("proposal group absent"))?
                .validate_proposal_response(&proposal, &intent)?;
            proposal.mutation
        } else {
            decode(&receipt.response_bytes, "source-aware write response")?
        };
        if receipt.schema_version != SCHEMA_VERSION
            || receipt.operation != event.operation
            || receipt.request_digest != event.request_digest
            || receipt.response_digest != event.response_digest
            || digest_bytes(&receipt.response_bytes) != event.response_digest
            || response.replayed
            || response.commit_seq != event.workspace_commit
            || response.watermarks.journal != event.workspace_commit
            || response.request_digest != event.request_digest
        {
            return Err(integrity(
                "source-aware write retry receipt differs from its accepted event",
            ));
        }
        Ok(intent)
    }

    pub(super) fn verified_record_write_intent<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &StoredEvent,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RecordWriteIntent> {
        let intent = self.budgeted_record_write_intent(snapshot, event, &mut Some(budget))?;
        if intent.group.is_some() {
            self.verified_record_group(snapshot, event, &intent, budget)?;
            return Ok(intent);
        }
        if self.record_write_has_pruned_members(snapshot, event, budget)? {
            self.verify_local_record_origin(snapshot, &intent.origins[0], budget)?;
            return Ok(intent);
        }
        let control = &intent.origins[0];
        let reference = &intent.records[0];
        let bytes = snapshot
            .get(&self.keyspaces.continuous, &reference.key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("source-aware accepted record absent"))?;
        budget
            .charge(1, bytes.len() as u64)
            .map_err(raw_index::budget_error)?;
        let record: MemoryRecord = decode(&bytes, "source-aware accepted record")?;
        if control.workspace != intent.workspace
            || control.transaction_from != event.global_commit
            || record.transaction_from != event.global_commit
            || record.transaction_to.is_some()
            || control.revision != 1
            || record.revision != 1
            || record.document.kind != MemoryRecordKind::SemanticObject
            || record.document.lifecycle != MemoryLifecycle::Active
            || digest_bytes(record.document.access.workspace_id.as_bytes()) != intent.workspace
            || digest_bytes(record.document.id.as_bytes()) != control.record_digest
            || control.birth_digest != reference.digest
            || reference.digest != digest_bytes(&bytes)
            || control.document_digest != canonical_digest(&record.document)?
            || control.scopes != record.document.access.scopes
            || !(1..=64).contains(&control.sources.len())
            || reference.key
                != format!(
                    "semantic/record/{:020}/{}/{:010}",
                    event.global_commit, control.record_digest, control.revision
                )
                .as_bytes()
        {
            return Err(integrity(
                "record source intent omits or changes a birth mutation",
            ));
        }
        // Accepted sources precede this actual birth, including after recovery
        // with unrelated captures or restored native snapshots.
        for id in control.sources.keys() {
            let source: StoredObservationPolicy = decode(
                &snapshot
                    .get(
                        &self.keyspaces.observations_policy,
                        digest_bytes(id.to_string().as_bytes()).as_bytes(),
                    )
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("record input policy absent"))?,
                "record input policy",
            )?;
            if source.accepted_global_commit >= event.global_commit
                || source.access.workspace_id != record.document.access.workspace_id
            {
                return Err(integrity(
                    "record input does not precede its accepted birth",
                ));
            }
        }
        if snapshot
            .get(
                &self.keyspaces.policy_history,
                &history_key(&control.record_digest, control.revision),
            )
            .map_err(storage_error)?
            .is_none()
        {
            return Err(integrity(
                "accepted source-aware record lost its projection",
            ));
        }
        self.verify_local_record_origin(snapshot, control, budget)?;
        Ok(intent)
    }

    pub(crate) fn check_record_write_origin<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        control: &RecordSourceControl,
    ) -> ServiceResult<()> {
        let event: StoredEvent = decode(
            &snapshot
                .get(
                    &self.keyspaces.events,
                    &control.transaction_from.to_be_bytes(),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("record birth event absent"))?,
            "record birth event",
        )?;
        if is_source_write(&event.operation)
            && !self
                .record_write_intent(snapshot, &event)?
                .origins
                .contains(control)
        {
            return Err(invalid(
                "record origins differ from its accepted source intent",
            ));
        }
        Ok(())
    }

    pub(crate) fn verify_record_writes<S: ReadSnapshot>(&self, snapshot: &S) -> ServiceResult<()> {
        let mut expected = BTreeMap::new();
        let mut intents = BTreeMap::new();
        let mut prefixes = BTreeMap::new();
        let mut budget = retention::audit_budget();
        for row in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: StoredEvent = decode(&row.value, "record write history")?;
            if let Some(applied) = &event.accepted_record_sources {
                prefixes.insert(event.workspace_digest.clone(), applied.through.clone());
            }
            if is_source_write(&event.operation) {
                let intent = self.verified_record_write_intent(snapshot, &event, &mut budget)?;
                expected.insert(intent_key(event.global_commit), encode(&intent)?);
                intents.insert(event.global_commit, intent);
            } else if event.accepted_record_write.is_some() {
                return Err(integrity("source intent belongs to an invalid operation"));
            }
            if event.operation != COMPLETE {
                if event.accepted_record_write_completion.is_some() {
                    return Err(integrity(
                        "source completion belongs to an invalid operation",
                    ));
                }
                continue;
            }
            let publication = event
                .accepted_record_write_completion
                .as_ref()
                .ok_or_else(|| integrity("record write completion lost its reference"))?;
            let write = self.record_write_event(snapshot, publication.write_global_commit)?;
            let intent = intents
                .get(&publication.write_global_commit)
                .ok_or_else(|| integrity("record completion precedes its accepted intent"))?;
            let scopes = intent.scopes();
            if self.record_write_completion(snapshot, &write)?.as_ref() != Some(&event)
                || prefixes.get(&event.workspace_digest) != Some(&publication.through)
                || publication.scopes != scopes
            {
                return Err(integrity(
                    "record completion omits its applied origins or scope epoch",
                ));
            }
            self.verify_record_write_bindings(intent, &publication.through, &mut budget)?;
            if expected
                .insert(
                    completion_key(write.global_commit),
                    encode(&CompletedWrite {
                        global_commit: event.global_commit,
                        publication: publication.clone(),
                    })?,
                )
                .is_some()
            {
                return Err(integrity("record write completed more than once"));
            }
        }
        let manifest: Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("record write manifest absent"))?,
            "record write manifest",
        )?;
        let actual = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"record-write/")
            .map_err(storage_error)?;
        if manifest.features.contains(WRITE_FEATURE) == intents.is_empty()
            || manifest.features.contains(GROUP_FEATURE)
                != intents.values().any(|intent| intent.group.is_some())
            || manifest.features.contains(CORRECTION_FEATURE)
                != intents.values().any(|intent| {
                    intent
                        .group
                        .as_ref()
                        .is_some_and(|group| group.is_correction())
                })
            || actual.len() != expected.len()
            || actual
                .iter()
                .any(|row| expected.get(&row.key) != Some(&row.value))
        {
            return Err(integrity(
                "record write intent or completion family differs from accepted history",
            ));
        }
        let receipt_keys: BTreeSet<_> = intents
            .values()
            .map(|intent| intent.idempotency_key.clone())
            .collect();
        if receipt_keys.len() != intents.len() {
            return Err(integrity("record source writes share a retry receipt"));
        }
        for row in snapshot
            .scan_prefix(&self.keyspaces.idempotency, b"")
            .map_err(storage_error)?
        {
            let receipt: StoredIdempotency = decode(&row.value, "record write retry closure")?;
            if is_source_write(&receipt.operation) && !receipt_keys.contains(&row.key) {
                return Err(integrity("orphaned source-aware write retry receipt"));
            }
        }
        Ok(())
    }
}
