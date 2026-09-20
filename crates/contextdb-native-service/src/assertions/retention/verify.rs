//! Reconstruct the exact accepted transition from full to pruned batches.

use super::*;

pub(in super::super) struct PruningBinding {
    receipt: AssertionReceipt,
    control: BatchControl,
    removed: BTreeMap<usize, (String, u64)>,
}

impl NativeService {
    pub(in super::super) fn assertion_pruning_bindings<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<(String, u64), PruningBinding>> {
        let manifest: crate::Manifest = self.raw_manifest(snapshot)?;
        let mut bindings = BTreeMap::<(String, u64), PruningBinding>::new();
        let mut batches = BTreeMap::<(String, u64), RetainedAssertions>::new();
        let mut after = None;
        loop {
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.events,
                    ScanPageRequest {
                        prefix: b"",
                        start_after: after.as_deref(),
                        max_entries: 256,
                        max_bytes: 8 * 1024 * 1024,
                    },
                )
                .map_err(storage_error)?;
            for row in page.entries {
                budget
                    .charge(1, row.value.len() as u64)
                    .map_err(budget_error)?;
                let event: crate::StoredEvent = decode(&row.value, "assertion pruning journal")?;
                after = Some(row.key);
                let Some(publication) = &event.accepted_assertion_pruning else {
                    if event.operation == "assertion_prune" {
                        return Err(integrity("assertion pruning lost its accepted reference"));
                    }
                    continue;
                };
                let workspace = &event.workspace_digest;
                let batch_id = (workspace.clone(), publication.receipt.workspace_commit);
                let batch = match batches.entry(batch_id) {
                    std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        let bytes = snapshot
                            .get(
                                &self.keyspaces.continuous,
                                &retained_key(workspace, publication.receipt.workspace_commit),
                            )
                            .map_err(storage_error)?
                            .ok_or_else(|| integrity("pruned assertion control is absent"))?;
                        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
                        entry.insert(decode(&bytes, "pruned assertion control")?)
                    }
                };
                let control = &batch.control;
                let digest = pruning_digest(workspace, &publication.request, control.commit)?;
                let (global, original_world) =
                    self.select_snapshot(snapshot, &control.workspace_id, Some(control.commit))?;
                let original: crate::StoredEvent = decode(
                    &snapshot
                        .get(&self.keyspaces.events, &global.to_be_bytes())
                        .map_err(storage_error)?
                        .ok_or_else(|| integrity("pruned assertion acceptance absent"))?,
                    "pruned assertion acceptance",
                )?;
                if event.operation != "assertion_prune"
                    || !manifest.features.contains(PRUNING_FEATURE)
                    || event.event_digest != crate::event_digest(&event)?
                    || publication.workspace_commit != event.workspace_commit
                    || control.commit >= event.workspace_commit
                    || original_world.watermarks.journal != control.commit
                    || original.workspace_digest != *workspace
                    || original.operation != "assertions"
                    || original.accepted_assertions.as_ref() != Some(&publication.receipt)
                    || original.request_digest != control.request_digest
                    || original.event_digest != crate::event_digest(&original)?
                    || publication.receipt.workspace_commit != control.commit
                    || publication.receipt.database_id != self.database_id
                    || publication.receipt.domain != DOMAIN
                    || publication.control_digest != canonical_digest(control)?
                    || control.mutations.len() > 64
                    || publication.removed.is_empty()
                    || publication.removed.len() > 64
                    || publication.selected_sources.is_empty()
                    || event.request_digest != digest
                    || event.response_digest != digest_bytes(&encode(publication)?)
                    || digest_bytes(control.workspace_id.as_bytes()) != *workspace
                {
                    return Err(integrity("assertion pruning publication binding differs"));
                }
                let retry = self.replay::<AssertionPruningPublication, _>(
                    snapshot,
                    digest.as_bytes(),
                    "assertion_prune",
                    &digest,
                )?;
                if retry.as_ref() != Some(publication) {
                    return Err(integrity("assertion pruning lost its exact retry receipt"));
                }
                let ledger = self
                    .suppression
                    .as_ref()
                    .ok_or_else(|| integrity("assertion removal authority absent"))?;
                for id in &publication.selected_sources {
                    let source =
                        ledger.removal_source(workspace, &publication.request, *id, budget)?;
                    self.verify_retained_capture_control(snapshot, &source, budget)?;
                    if !self.source_prepared_at(
                        snapshot,
                        workspace,
                        *id,
                        Some(publication.workspace_commit),
                        budget,
                    )? {
                        return Err(integrity("assertion source was not prepared for removal"));
                    }
                }
                let binding = bindings
                    .entry((workspace.clone(), control.commit))
                    .or_insert_with(|| PruningBinding {
                        receipt: publication.receipt.clone(),
                        control: control.clone(),
                        removed: BTreeMap::new(),
                    });
                if binding.receipt != publication.receipt || binding.control != *control {
                    return Err(integrity(
                        "assertion pruning changed its original batch control",
                    ));
                }
                for (ordinal, removed_digest) in &publication.removed {
                    let Some(RetainedMutation::Removed {
                        control: removed,
                        at,
                    }) = batch.mutations.get(*ordinal)
                    else {
                        return Err(integrity(
                            "accepted removal has no retained mutation control",
                        ));
                    };
                    if control.mutations.get(*ordinal) != Some(&removed.body_digest)
                        || *at != publication.workspace_commit
                        || canonical_digest(removed)? != *removed_digest
                        || removed.key.scope != control.scope
                        || removed.sources.is_empty()
                        || removed.sources.len() > 64
                        || !removed.sources.contains(&removed.origin)
                        || removed.sources.is_disjoint(&publication.selected_sources)
                        || removed.valid_time.validate().is_err()
                        || binding
                            .removed
                            .insert(
                                *ordinal,
                                (removed_digest.clone(), publication.workspace_commit),
                            )
                            .is_some()
                    {
                        return Err(integrity(
                            "assertion removal has no exact authorized mutation",
                        ));
                    }
                }
                if publication.selected_sources.iter().any(|id| {
                    !publication.removed.keys().any(|ordinal| {
                        matches!(batch.mutations.get(*ordinal), Some(RetainedMutation::Removed { control, .. }) if control.sources.contains(id))
                    })
                }) {
                    return Err(integrity("assertion pruning contains an unrelated source"));
                }
            }
            if page.continuation.is_none() {
                break;
            }
        }
        Ok(bindings)
    }

    pub(in super::super) fn load_retained_assertions<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &crate::StoredEvent,
        binding: Option<&PruningBinding>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(Vec<u8>, Vec<u8>, RetainedAssertions)> {
        let receipt = event
            .accepted_assertions
            .as_ref()
            .ok_or_else(|| integrity("assertion receipt absent"))?;
        let full_key = journal_key(&event.workspace_digest, event.workspace_commit);
        let pruned_key = retained_key(&event.workspace_digest, event.workspace_commit);
        let (key, bytes, batch) = if let Some(binding) = binding {
            if snapshot
                .get(&self.keyspaces.continuous, &full_key)
                .map_err(storage_error)?
                .is_some()
            {
                return Err(integrity("pruned assertion payload was resurrected"));
            }
            let bytes = snapshot
                .get(&self.keyspaces.continuous, &pruned_key)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("pruned assertion control is absent"))?;
            budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
            let batch: RetainedAssertions = decode(&bytes, "pruned assertion batch")?;
            if binding.receipt != *receipt || binding.control != batch.control {
                return Err(integrity(
                    "pruned assertion control differs from acceptance",
                ));
            }
            for (ordinal, mutation) in batch.mutations.iter().enumerate() {
                match (mutation, binding.removed.get(&ordinal)) {
                    (RetainedMutation::Live { .. }, None) => {}
                    (RetainedMutation::Removed { control, at }, Some((expected, commit)))
                        if canonical_digest(control)? == *expected && at == commit => {}
                    _ => {
                        return Err(integrity(
                            "pruned assertion mutation set differs from its journal",
                        ));
                    }
                }
            }
            (pruned_key, bytes, batch)
        } else {
            let bytes = snapshot
                .get(&self.keyspaces.continuous, &full_key)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("accepted semantic payload is absent"))?;
            budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
            if ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes())
                != receipt.mutation_digest
            {
                return Err(integrity("accepted semantic payload digest differs"));
            }
            let accepted: AcceptedAssertions = decode(&bytes, "accepted semantic payload")?;
            accepted
                .pipeline
                .validate()
                .map_err(|_| integrity("accepted interpreter identity invalid"))?;
            (
                full_key,
                bytes,
                RetainedAssertions::from_accepted(&accepted)?,
            )
        };
        if batch.mutations.len() != batch.control.mutations.len() || batch.mutations.len() > 64 {
            return Err(integrity("retained assertion mutation count differs"));
        }
        for (ordinal, mutation) in batch.mutations.iter().enumerate() {
            let (digest, scope) = match mutation {
                RetainedMutation::Live { mutation } => {
                    (digest_bytes(&encode(mutation)?), mutation.key().scope)
                }
                RetainedMutation::Removed { control, .. } => {
                    (control.body_digest.clone(), control.key.scope)
                }
            };
            if batch.control.mutations[ordinal] != digest || scope != batch.control.scope {
                return Err(integrity("retained assertion mutation commitment differs"));
            }
        }
        Ok((key, bytes, batch))
    }
}
