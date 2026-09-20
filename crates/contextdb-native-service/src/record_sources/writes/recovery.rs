use super::*;

impl NativeService {
    /// Resume an accepted source-aware mutation from its workspace-local commit.
    /// Only accepted controls are transferred; original request bodies are not
    /// needed. Revocation may close reads while administrative repair continues.
    pub fn resume_record_source_write(
        &self,
        context: &AuthenticatedRequestContext,
        commit_seq: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRecordWriteReceipt> {
        self.complete_record_source_write(context, commit_seq, None, budget)
    }

    pub(super) fn complete_record_source_write(
        &self,
        context: &AuthenticatedRequestContext,
        commit_seq: u64,
        response: Option<&MutationResponse>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRecordWriteReceipt> {
        require_capability(context, Capability::Admin)?;
        budget.check().map_err(raw_index::budget_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let mapping: CommitMap = decode(
            &snapshot
                .get(
                    &self.keyspaces.workspace_map,
                    &workspace_map_key(&workspace, commit_seq),
                )
                .map_err(storage_error)?
                .ok_or_else(not_found)?,
            "record write commit mapping",
        )?;
        validate_workspace_state(&mapping.state, &workspace)?;
        let event = self.record_write_event(&snapshot, mapping.global_commit)?;
        if commit_seq == 0
            || mapping.schema_version != SCHEMA_VERSION
            || mapping.state.latest_global_commit != mapping.global_commit
            || mapping.state.watermarks.journal != commit_seq
            || event.workspace_digest != workspace
            || event.workspace_commit != commit_seq
        {
            return Err(integrity("record write commit mapping differs"));
        }
        if let Some(response) = response {
            let mut original = response.clone();
            original.replayed = false;
            if event.request_digest != original.request_digest
                || event.response_digest != canonical_digest(&original)?
            {
                return Err(integrity(
                    "record write retry receipt differs from its accepted event",
                ));
            }
        }
        let intent = self.verified_record_write_intent(&snapshot, &event, budget)?;
        let accepted_world = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        if let Some(completed) = self.record_write_completion(&snapshot, &event)? {
            return Ok(NativeRecordWriteReceipt {
                commit_seq,
                completed_at: completed.workspace_commit,
            });
        }
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("record source authority absent"))?;
        for control in &intent.origins {
            // The actual accepted birth is fixed. No predicted commit is ever
            // reserved in the independently retained authority.
            {
                let _guard = self.lock_index_publication(budget)?;
                let latest = self
                    .engine
                    .begin_read(SnapshotSelector::Latest)
                    .map_err(storage_error)?;
                if self.workspace_state(&latest, &context.request.workspace_id)? != accepted_world
                    || self.record_write_event(&latest, event.global_commit)? != event
                {
                    return Err(pending(
                        "workspace changed while transferring record origins",
                    ));
                }
                ledger.bind_record_origin(control, budget)?;
            }
            #[cfg(test)]
            AFTER_ORIGIN_SYNC.with(|hook| {
                if let Some(hook) = hook.take() {
                    hook();
                }
            });
        }
        while !self
            .maintain_record_sources(context, 256, budget)?
            .caught_up
        {}
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let world = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        let through = self.record_sources_applied(&snapshot, &workspace)?;
        self.verify_record_write_bindings(&intent, &through, budget)?;
        let publication = RecordWriteCompletion {
            write_global_commit: event.global_commit,
            intent_digest: event
                .accepted_record_write
                .as_ref()
                .ok_or_else(|| integrity("record write reference absent"))?
                .digest
                .clone(),
            through: through.clone(),
            scopes: intent
                .origins
                .iter()
                .flat_map(|control| control.scopes.iter().cloned())
                .collect(),
        };
        #[cfg(test)]
        BEFORE_COMPLETION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if let Some(completed) = self.record_write_completion(&tx, &event)? {
            return Ok(NativeRecordWriteReceipt {
                commit_seq,
                completed_at: completed.workspace_commit,
            });
        }
        if self.workspace_state(&tx, &context.request.workspace_id)? != world
            || self.record_sources_applied(&tx, &workspace)? != through
            || self.record_write_event(&tx, event.global_commit)? != event
        {
            return Err(pending(
                "workspace changed while completing record publication",
            ));
        }
        self.require_record_sources_current(&tx, &workspace)?;
        let frame = self.begin_frame(&tx, &context.request.workspace_id, false)?;
        for scope in &publication.scopes {
            tx.put(
                &self.keyspaces.continuous,
                capture::scope_key(&workspace, scope),
                encode(&frame.state.watermarks.journal)?,
            )
            .map_err(storage_error)?;
        }
        tx.put(
            &self.keyspaces.continuous,
            completion_key(event.global_commit),
            encode(&CompletedWrite {
                global_commit: frame.global_commit,
                publication: publication.clone(),
            })?,
        )
        .map_err(storage_error)?;
        let digest = canonical_digest(&(WRITE_FEATURE, COMPLETE, &workspace, &publication))?;
        self.finish_frame(
            &mut tx,
            &frame,
            COMPLETE,
            digest.as_bytes(),
            &digest,
            &publication,
        )?;
        budget.check().map_err(raw_index::budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(NativeRecordWriteReceipt {
            commit_seq,
            completed_at: frame.state.watermarks.journal,
        })
    }

    pub(super) fn record_write_event<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        global: u64,
    ) -> ServiceResult<StoredEvent> {
        let event: StoredEvent = decode(
            &snapshot
                .get(&self.keyspaces.events, &global.to_be_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("record write journal absent"))?,
            "record write journal",
        )?;
        if event.schema_version != SCHEMA_VERSION
            || event.global_commit != global
            || event.operation != PUBLISH
            || event.event_digest != event_digest(&event)?
            || event.accepted_record_write.is_none()
        {
            return Err(integrity("record write journal binding differs"));
        }
        Ok(event)
    }

    pub(super) fn verify_record_write_bindings(
        &self,
        intent: &RecordWriteIntent,
        through: &RecordSourcesCheckpoint,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("record source authority absent"))?;
        for control in &intent.origins {
            budget
                .charge(1, encode(control)?.len() as u64)
                .map_err(raw_index::budget_error)?;
            let binding = ledger
                .retained_record_sources(
                    &intent.workspace,
                    &control.record_digest,
                    control.revision,
                )?
                .ok_or_else(|| integrity("completed record write lost its retained origins"))?;
            if binding.record_control()? != control
                || binding.checkpoint.epoch > through.epoch
                || (binding.checkpoint.epoch == through.epoch
                    && binding.checkpoint.digest != through.digest)
            {
                return Err(integrity(
                    "completed record write precedes its retained origins",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn record_write_completion<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        write: &StoredEvent,
    ) -> ServiceResult<Option<StoredEvent>> {
        let intent = self.record_write_intent(snapshot, write)?;
        let Some(bytes) = snapshot
            .get(
                &self.keyspaces.continuous,
                &completion_key(write.global_commit),
            )
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        let marker: CompletedWrite = decode(&bytes, "record write completion marker")?;
        let event: StoredEvent = decode(
            &snapshot
                .get(&self.keyspaces.events, &marker.global_commit.to_be_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("record write completion event absent"))?,
            "record write completion event",
        )?;
        if event.schema_version != SCHEMA_VERSION
            || event.operation != COMPLETE
            || event.global_commit != marker.global_commit
            || event.global_commit <= write.global_commit
            || event.workspace_digest != write.workspace_digest
            || event.workspace_commit <= write.workspace_commit
            || marker.publication.write_global_commit != write.global_commit
            || write
                .accepted_record_write
                .as_ref()
                .map(|reference| &reference.digest)
                != Some(&marker.publication.intent_digest)
            || event.accepted_record_write_completion.as_ref() != Some(&marker.publication)
            || marker.publication.scopes
                != intent
                    .origins
                    .iter()
                    .flat_map(|control| control.scopes.iter().cloned())
                    .collect()
            || event.event_digest != event_digest(&event)?
            || event.response_digest != canonical_digest(&marker.publication)?
            || event.request_digest
                != canonical_digest(&(
                    WRITE_FEATURE,
                    COMPLETE,
                    &event.workspace_digest,
                    &marker.publication,
                ))?
        {
            return Err(integrity("record write completion is not journal-bound"));
        }
        let applied = self.record_sources_applied(snapshot, &write.workspace_digest)?;
        if applied.epoch < marker.publication.through.epoch
            || (applied.epoch == marker.publication.through.epoch
                && applied != marker.publication.through)
        {
            return Err(integrity(
                "record write completion lacks applied provenance",
            ));
        }
        Ok(Some(event))
    }

    pub(crate) fn require_record_write_complete<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        policy: &StoredPolicy,
    ) -> ServiceResult<()> {
        // Both a new revision and a closure can belong to an interrupted group.
        for global in [Some(policy.transaction_from), policy.transaction_to]
            .into_iter()
            .flatten()
        {
            let event: StoredEvent = decode(
                &snapshot
                    .get(&self.keyspaces.events, &global.to_be_bytes())
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("record acceptance event absent"))?,
                "record acceptance event",
            )?;
            if event.operation == PUBLISH {
                let write = self.record_write_event(snapshot, global)?;
                if self.record_write_completion(snapshot, &write)?.is_none() {
                    return Err(pending("accepted record source handoff is incomplete"));
                }
            } else if event.accepted_record_write.is_some() {
                return Err(integrity("record source write has an invalid operation"));
            }
        }
        Ok(())
    }
}
