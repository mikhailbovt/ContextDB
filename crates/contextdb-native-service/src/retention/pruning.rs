//! Logical primary-body removal. Other copy classes and erasure remain pending.

use contextdb_core::ContentDigest;

use super::*;

pub(crate) const PRUNING_FEATURE: &str = "continuous-source-pruning-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrunedControl {
    capture: ContentDigest,
    policy: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourcePruningPublication {
    request: RemovalCheckpoint,
    workspace_commit: u64,
    sources: BTreeMap<ObservationId, PrunedControl>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrunedSource {
    request: RemovalCheckpoint,
    workspace_commit: u64,
    event_id: ObservationId,
    control: PrunedControl,
}

/// Primary body rows removed by one native Sync. This is not a completion or
/// physical-erasure receipt; staged, semantic, external and key copies differ.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSourcePruningReceipt {
    /// Native workspace position retaining the removal evidence.
    pub workspace_commit: u64,
    /// Exact primary originals covered by this publication.
    pub sources: BTreeSet<ObservationId>,
}

impl NativeService {
    /// Remove 1..256 primary body rows after verified preparation and raw-copy
    /// reclamation. Affected assertions and generic revisions must be pruned
    /// first; unclassified generic revisions block removal of primary originals.
    /// All other retention gates remain closed after this operation.
    pub fn prune_original_sources(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &NativeRemovalRequestReceipt,
        sources: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeSourcePruningReceipt> {
        require_capability(context, Capability::Admin)?;
        if !(1..=256).contains(&sources.len()) {
            return Err(invalid("primary pruning requires 1..256 source IDs"));
        }
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("primary pruning requires retained authority"))?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let request = RemovalCheckpoint {
            sequence: receipt.sequence,
            digest: receipt.digest.clone(),
        };
        let intent = ledger.retained_removal_intent(&workspace, &request)?;
        if removal_receipt(ledger, &request, &intent) != *receipt {
            return Err(invalid("primary pruning receipt differs"));
        }
        let digest = pruning_digest(&workspace, &request, sources)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if let Some(accepted) = self.replay::<SourcePruningPublication, _>(
            &snapshot,
            digest.as_bytes(),
            "source_prune",
            &digest,
        )? {
            return Ok(pruning_receipt(&accepted));
        }
        drop(snapshot);
        // Fresh accepted-history discovery also detects descendants absent from
        // the earlier request. Such a request needs an authority extension first.
        let closure = self.inspect_original_deletion(context, sources, budget)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let world = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        if world.watermarks.journal != closure.workspace_commit {
            return Err(removal_pending());
        }
        self.require_custody_rebuilt(&snapshot, &workspace)?;
        self.require_primary_pruning_semantics_ready(
            &snapshot,
            &workspace,
            &closure
                .sources
                .iter()
                .map(|source| source.receipt.event_id)
                .collect(),
            budget,
        )?;
        for source in &closure.sources {
            let id = source.receipt.event_id;
            if ledger.removal_source(&workspace, &request, id, budget)? != *source
                || !self.source_prepared_at(
                    &snapshot,
                    &workspace,
                    id,
                    Some(world.watermarks.journal),
                    budget,
                )?
            {
                return Err(removal_pending());
            }
            self.require_raw_source_prunable(&snapshot, &workspace, &source.receipt, budget)?;
        }
        let mut controls = BTreeMap::new();
        for id in sources {
            let source = ledger.removal_source(&workspace, &request, *id, budget)?;
            let policy = self.pruning_policy(&snapshot, *id)?;
            if policy.access.retrievable {
                return Err(integrity("primary removal source is still retrievable"));
            }
            controls.insert(
                *id,
                PrunedControl {
                    capture: source.control_digest,
                    policy: canonical_digest(&policy)?,
                },
            );
        }
        #[cfg(test)]
        BEFORE_PUBLICATION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if let Some(accepted) = self.replay::<SourcePruningPublication, _>(
            &tx,
            digest.as_bytes(),
            "source_prune",
            &digest,
        )? {
            return Ok(pruning_receipt(&accepted));
        }
        if self.workspace_state(&tx, &context.request.workspace_id)? != world {
            return Err(removal_pending());
        }
        let frame = self.begin_frame(&tx, &context.request.workspace_id, false)?;
        let publication = SourcePruningPublication {
            request,
            workspace_commit: frame.state.watermarks.journal,
            sources: controls,
        };
        for (id, control) in &publication.sources {
            let observation = digest_bytes(id.to_string().as_bytes());
            // Overlapping batches retain the first accepted tombstone identity.
            if tx
                .get(&self.keyspaces.continuous, &pruned_key(&observation))
                .map_err(storage_error)?
                .is_none()
            {
                tx.put(
                    &self.keyspaces.continuous,
                    pruned_key(&observation),
                    encode(&PrunedSource {
                        request: publication.request.clone(),
                        workspace_commit: publication.workspace_commit,
                        event_id: *id,
                        control: control.clone(),
                    })?,
                )
                .map_err(storage_error)?;
            }
            tx.delete(
                &self.keyspaces.observations_content,
                observation.as_bytes().to_vec(),
            )
            .map_err(storage_error)?;
        }
        self.enable_capture_extension(&mut tx, PRUNING_FEATURE)?;
        self.finish_frame(
            &mut tx,
            &frame,
            "source_prune",
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
        Ok(pruning_receipt(&publication))
    }

    pub(crate) fn verify_pruned_source<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<ContentDigest>> {
        let observation = digest_bytes(id.to_string().as_bytes());
        let Some(bytes) = snapshot
            .get(&self.keyspaces.continuous, &pruned_key(&observation))
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        budget
            .charge(1, bytes.len() as u64)
            .map_err(raw_index::budget_error)?;
        let marker: PrunedSource = decode(&bytes, "pruned original marker")?;
        let policy = self.pruning_policy(snapshot, id)?;
        let workspace = digest_bytes(policy.access.workspace_id.as_bytes());
        let manifest: Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("pruning format is absent"))?,
            "pruning format",
        )?;
        if marker.event_id != id
            || !manifest.features.contains(PRUNING_FEATURE)
            || policy.access.retrievable
            || policy.observation_digest != observation
            || canonical_digest(&policy)? != marker.control.policy
            || snapshot
                .get(&self.keyspaces.observations_content, observation.as_bytes())
                .map_err(storage_error)?
                .is_some()
            || !self.source_prepared_at(
                snapshot,
                &workspace,
                id,
                Some(marker.workspace_commit),
                budget,
            )?
        {
            return Err(integrity(
                "pruned original body, policy or preparation differs",
            ));
        }
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("pruned authority is absent"))?;
        let retained = ledger.removal_source(&workspace, &marker.request, id, budget)?;
        self.verify_retained_capture_control(snapshot, &retained, budget)?;
        let (capture_global, _) = self.select_snapshot(
            snapshot,
            &policy.access.workspace_id,
            Some(retained.receipt.workspace_commit),
        )?;
        let (global, _) = self.select_snapshot(
            snapshot,
            &policy.access.workspace_id,
            Some(marker.workspace_commit),
        )?;
        let bytes = snapshot
            .get(&self.keyspaces.events, &global.to_be_bytes())
            .map_err(storage_error)?
            .ok_or_else(|| integrity("primary removal journal is absent"))?;
        budget
            .charge(1, bytes.len() as u64)
            .map_err(raw_index::budget_error)?;
        let event: StoredEvent = decode(&bytes, "primary removal journal")?;
        if retained.control_digest != marker.control.capture
            || capture_global != policy.accepted_global_commit
            || retained.receipt.workspace_commit >= marker.workspace_commit
            || event.operation != "source_prune"
            || event.workspace_digest != workspace
            || event.workspace_commit != marker.workspace_commit
            || event.event_digest != event_digest(&event)?
            || event
                .accepted_source_pruning
                .as_ref()
                .is_none_or(|publication| {
                    publication.request != marker.request
                        || publication.workspace_commit != marker.workspace_commit
                        || publication.sources.get(&id) != Some(&marker.control)
                })
        {
            return Err(integrity(
                "primary removal is not bound to its accepted journal",
            ));
        }
        Ok(Some(marker.control.capture))
    }

    pub(crate) fn verify_pruned_observation<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        policy: &StoredObservationPolicy,
    ) -> ServiceResult<()> {
        let bytes = snapshot
            .get(
                &self.keyspaces.continuous,
                &pruned_key(&policy.observation_digest),
            )
            .map_err(storage_error)?
            .ok_or_else(|| integrity("native observation content is absent without removal"))?;
        let marker: PrunedSource = decode(&bytes, "pruned observation")?;
        let mut budget = audit_budget();
        if self
            .verify_pruned_source(snapshot, marker.event_id, &mut budget)?
            .is_none()
            || self.pruning_policy(snapshot, marker.event_id)? != *policy
        {
            return Err(integrity("pruned observation policy binding differs"));
        }
        Ok(())
    }

    pub(crate) fn verify_source_pruning<S: ReadSnapshot>(&self, snapshot: &S) -> ServiceResult<()> {
        let mut expected = BTreeMap::new();
        let mut budget = audit_budget();
        for row in snapshot
            .scan_prefix(&self.keyspaces.continuous, b"removal/")
            .map_err(storage_error)?
        {
            if !row.key.starts_with(b"removal/prepared/")
                && !row.key.starts_with(b"removal/pruned/")
            {
                return Err(integrity("unknown native removal record family"));
            }
        }
        for row in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: StoredEvent = decode(&row.value, "primary pruning journal")?;
            let Some(publication) = &event.accepted_source_pruning else {
                if event.operation == "source_prune" {
                    return Err(integrity("primary pruning journal reference is missing"));
                }
                continue;
            };
            let ids = publication.sources.keys().copied().collect();
            if event.operation != "source_prune"
                || !(1..=256).contains(&publication.sources.len())
                || publication.workspace_commit != event.workspace_commit
                || event.request_digest
                    != pruning_digest(&event.workspace_digest, &publication.request, &ids)?
                || event.response_digest != digest_bytes(&encode(publication)?)
            {
                return Err(integrity("primary pruning publication binding differs"));
            }
            let ledger = self
                .suppression
                .as_ref()
                .ok_or_else(|| integrity("pruning authority is missing"))?;
            for (id, control) in &publication.sources {
                let retained = ledger.removal_source(
                    &event.workspace_digest,
                    &publication.request,
                    *id,
                    &mut budget,
                )?;
                if retained.control_digest != control.capture
                    || retained.receipt.workspace_commit >= event.workspace_commit
                {
                    return Err(integrity("primary pruning source differs from authority"));
                }
                self.verify_pruned_source(snapshot, *id, &mut budget)?
                    .ok_or_else(|| integrity("primary pruning marker is missing"))?;
                expected
                    .entry(pruned_key(&digest_bytes(id.to_string().as_bytes())))
                    .or_insert(encode(&PrunedSource {
                        request: publication.request.clone(),
                        workspace_commit: publication.workspace_commit,
                        event_id: *id,
                        control: control.clone(),
                    })?);
            }
        }
        let actual = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"removal/pruned/")
            .map_err(storage_error)?;
        if actual.len() != expected.len()
            || actual
                .iter()
                .any(|row| expected.get(&row.key) != Some(&row.value))
        {
            return Err(integrity(
                "primary pruning markers differ from accepted history",
            ));
        }
        Ok(())
    }

    fn pruning_policy<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
    ) -> ServiceResult<StoredObservationPolicy> {
        let policy: StoredObservationPolicy = decode(
            &snapshot
                .get(
                    &self.keyspaces.observations_policy,
                    digest_bytes(id.to_string().as_bytes()).as_bytes(),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("pruning policy is absent"))?,
            "pruning policy",
        )?;
        validate_access(&policy.access)?;
        if policy.schema_version != SCHEMA_VERSION
            || policy.accepted_global_commit == 0
            || policy.observation_digest != digest_bytes(id.to_string().as_bytes())
        {
            return Err(integrity("primary pruning policy identity is invalid"));
        }
        Ok(policy)
    }

    // Semantic originals may disappear only after every affected mutation has
    // a verified pruned representation and no unclassified copy remains.
    fn require_primary_pruning_semantics_ready<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        sources: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.require_record_copies_pruned(snapshot, workspace, sources, budget)?;
        if !self
            .verify_assertion_records_budget(snapshot, budget)?
            .is_disjoint(sources)
        {
            return Err(unsupported(
                "prune source-supported assertion copies before primary originals",
            ));
        }
        Ok(())
    }
}

pub(crate) fn audit_budget() -> QueryBudget {
    QueryBudget::new(
        u64::MAX,
        u64::MAX,
        std::time::Duration::from_secs(3600),
        Default::default(),
    )
}
fn pruned_key(observation: &str) -> Vec<u8> {
    format!("removal/pruned/{observation}").into_bytes()
}
fn pruning_digest(
    workspace: &str,
    request: &RemovalCheckpoint,
    ids: &BTreeSet<ObservationId>,
) -> ServiceResult<String> {
    canonical_digest(&("native/source_prune/v1", workspace, request, ids))
}
fn pruning_receipt(publication: &SourcePruningPublication) -> NativeSourcePruningReceipt {
    NativeSourcePruningReceipt {
        workspace_commit: publication.workspace_commit,
        sources: publication.sources.keys().copied().collect(),
    }
}

#[cfg(test)]
thread_local! { static BEFORE_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default(); }

#[cfg(test)]
mod tests;
