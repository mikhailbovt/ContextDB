//! Native publication of verified control witnesses before pruning any bodies.

use contextdb_core::ContentDigest;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemovalPreparationPublication {
    request: RemovalCheckpoint,
    workspace_commit: u64,
    sources: BTreeMap<ObservationId, ContentDigest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedSource {
    request: RemovalCheckpoint,
    workspace_commit: u64,
    control_digest: ContentDigest,
}

/// Accepted preparation of immutable control metadata; no source has been erased.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRemovalPreparationReceipt {
    /// Native workspace commit that retained these verified controls.
    pub workspace_commit: u64,
    /// Sources prepared by this exact publication.
    pub sources: BTreeSet<ObservationId>,
}

impl NativeService {
    pub(crate) fn source_prepared_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        id: ObservationId,
        through: Option<u64>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<bool> {
        let Some(through) = through else {
            return Ok(false);
        };
        let Some(bytes) = snapshot
            .get(&self.keyspaces.continuous, &prepared_key(id))
            .map_err(storage_error)?
        else {
            return Ok(false);
        };
        budget
            .charge(1, bytes.len() as u64)
            .map_err(raw_index::budget_error)?;
        let prepared: PreparedSource = decode(&bytes, "prepared removal source")?;
        if prepared.workspace_commit > through {
            return Ok(false);
        }
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("prepared source has no retained authority"))?;
        let source = ledger.removal_source(workspace, &prepared.request, id, budget)?;
        if source.control_digest != prepared.control_digest {
            return Err(integrity(
                "prepared source commitment differs from retained authority",
            ));
        }
        self.verify_retained_capture_control(snapshot, &source, budget)?;
        let (global, _) = self.select_snapshot(
            snapshot,
            &source.receipt.workspace_id.to_string(),
            Some(prepared.workspace_commit),
        )?;
        let bytes = snapshot
            .get(&self.keyspaces.events, &global.to_be_bytes())
            .map_err(storage_error)?
            .ok_or_else(|| integrity("removal preparation journal is missing"))?;
        budget
            .charge(1, bytes.len() as u64)
            .map_err(raw_index::budget_error)?;
        let journal: StoredEvent = decode(&bytes, "removal preparation journal")?;
        if journal.operation != "removal_prepare"
            || journal.workspace_digest != workspace
            || journal.workspace_commit != prepared.workspace_commit
            || journal.event_digest != event_digest(&journal)?
            || journal
                .accepted_removal_preparation
                .as_ref()
                .is_none_or(|publication| {
                    publication.request != prepared.request
                        || publication.workspace_commit != prepared.workspace_commit
                        || publication.sources.get(&id) != Some(&prepared.control_digest)
                })
        {
            return Err(integrity(
                "prepared source lacks its accepted native publication",
            ));
        }
        Ok(true)
    }

    /// Prepare 1..256 captured sources from a retained removal request.
    /// Analysis verifies complete originals against their independently retained
    /// control commitments, then publishes all markers with one native Sync.
    /// Bodies remain present. Derived-copy cleanup must precede their pruning.
    pub fn prepare_original_removal_sources(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &NativeRemovalRequestReceipt,
        sources: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRemovalPreparationReceipt> {
        require_capability(context, Capability::Admin)?;
        if !(1..=256).contains(&sources.len()) {
            return Err(invalid("removal preparation requires 1..256 source IDs"));
        }
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("removal requires current authority"))?;
        if receipt.authority_id != ledger.authority_id() {
            return Err(invalid("removal preparation authority differs"));
        }
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let request = RemovalCheckpoint {
            sequence: receipt.sequence,
            digest: receipt.digest.clone(),
        };
        let intent = ledger.retained_removal_intent(&workspace, &request)?;
        if removal_receipt(ledger, &request, &intent) != *receipt {
            return Err(invalid("removal preparation request receipt differs"));
        }
        let digest =
            canonical_digest(&("native/removal_prepare/v1", &workspace, &request, sources))?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if let Some(accepted) = self.replay::<RemovalPreparationPublication, _>(
            &snapshot,
            digest.as_bytes(),
            "removal_prepare",
            &digest,
        )? {
            return Ok(preparation_receipt(&accepted));
        }
        let world = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        let mut controls = BTreeMap::new();
        for id in sources {
            let retained = ledger.removal_source(&workspace, &request, *id, budget)?;
            let original = self.load_captured_original(&snapshot, *id)?;
            budget
                .charge(1, encode(&original.event)?.len() as u64)
                .map_err(raw_index::budget_error)?;
            if original.receipt != retained.receipt
                || self.capture_control_digest(&snapshot, &original)? != retained.control_digest
                || self
                    .capture_work_for_receipt(&snapshot, &original.receipt)?
                    .recovery_digest
                    != Some(retained.recovery_digest)
            {
                return Err(integrity(
                    "removal preparation original differs from retained control",
                ));
            }
            controls.insert(*id, retained.control_digest);
        }
        #[cfg(test)]
        BEFORE_PUBLICATION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if let Some(accepted) = self.replay::<RemovalPreparationPublication, _>(
            &tx,
            digest.as_bytes(),
            "removal_prepare",
            &digest,
        )? {
            return Ok(preparation_receipt(&accepted));
        }
        if self.workspace_state(&tx, &context.request.workspace_id)? != world {
            return Err(removal_pending());
        }
        for id in sources {
            let revoke_digest =
                canonical_digest(&("removal/source-revocation/v1", &workspace, &request, id))?;
            self.revoke_original_in_transaction(
                &mut tx,
                context,
                *id,
                revoke_digest.as_bytes(),
                &revoke_digest,
            )?;
        }
        let frame = self.begin_frame(&tx, &context.request.workspace_id, false)?;
        let publication = RemovalPreparationPublication {
            request,
            workspace_commit: frame.state.watermarks.journal,
            sources: controls,
        };
        for (id, control_digest) in &publication.sources {
            if let Some(bytes) = tx
                .get(&self.keyspaces.continuous, &prepared_key(*id))
                .map_err(storage_error)?
            {
                let previous: PreparedSource = decode(&bytes, "previous prepared source")?;
                if previous.control_digest != *control_digest {
                    return Err(integrity("prepared source identity changed"));
                }
                continue;
            }
            tx.put(
                &self.keyspaces.continuous,
                prepared_key(*id),
                encode(&PreparedSource {
                    request: publication.request.clone(),
                    workspace_commit: publication.workspace_commit,
                    control_digest: *control_digest,
                })?,
            )
            .map_err(storage_error)?;
        }
        self.finish_frame(
            &mut tx,
            &frame,
            "removal_prepare",
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
        Ok(preparation_receipt(&publication))
    }

    pub(crate) fn verify_removal_preparations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<()> {
        let mut expected = BTreeMap::new();
        let mut budget = QueryBudget::new(
            u64::MAX,
            u64::MAX,
            std::time::Duration::from_secs(3600),
            Default::default(),
        );
        for row in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: StoredEvent = decode(&row.value, "removal preparation journal")?;
            let Some(publication) = &event.accepted_removal_preparation else {
                if event.operation == "removal_prepare" {
                    return Err(integrity("removal preparation lost its journal reference"));
                }
                continue;
            };
            let ids: BTreeSet<_> = publication.sources.keys().copied().collect();
            let digest = canonical_digest(&(
                "native/removal_prepare/v1",
                &event.workspace_digest,
                &publication.request,
                &ids,
            ))?;
            if event.operation != "removal_prepare"
                || ids.is_empty()
                || ids.len() > 256
                || publication.workspace_commit != event.workspace_commit
                || event.request_digest != digest
                || event.response_digest != digest_bytes(&encode(publication)?)
            {
                return Err(integrity("removal preparation journal binding differs"));
            }
            let ledger = self
                .suppression
                .as_ref()
                .ok_or_else(|| integrity("removal preparation has no retained authority"))?;
            for (id, control_digest) in &publication.sources {
                let retained = ledger.removal_source(
                    &event.workspace_digest,
                    &publication.request,
                    *id,
                    &mut budget,
                )?;
                if retained.control_digest != *control_digest
                    || retained.receipt.workspace_commit >= event.workspace_commit
                {
                    return Err(integrity(
                        "removal preparation differs from retained source",
                    ));
                }
                expected
                    .entry(prepared_key(*id))
                    .or_insert(encode(&PreparedSource {
                        request: publication.request.clone(),
                        workspace_commit: event.workspace_commit,
                        control_digest: *control_digest,
                    })?);
            }
        }
        let actual = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"removal/")
            .map_err(storage_error)?;
        if actual.len() != expected.len()
            || actual
                .iter()
                .any(|row| expected.get(&row.key) != Some(&row.value))
        {
            return Err(integrity(
                "prepared removal controls differ from their accepted publications",
            ));
        }
        for row in actual {
            let id: ObservationId = std::str::from_utf8(&row.key[b"removal/prepared/".len()..])
                .map_err(|_| integrity("prepared source ID is invalid"))?
                .parse()
                .map_err(|_| integrity("prepared source ID is invalid"))?;
            let prepared: PreparedSource = decode(&row.value, "prepared removal control")?;
            let original = self.load_captured_original(snapshot, id)?;
            if self.capture_control_digest(snapshot, &original)? != prepared.control_digest {
                return Err(integrity(
                    "prepared capture control changed after publication",
                ));
            }
        }
        Ok(())
    }
}

fn prepared_key(id: ObservationId) -> Vec<u8> {
    format!("removal/prepared/{id}").into_bytes()
}
fn preparation_receipt(
    publication: &RemovalPreparationPublication,
) -> NativeRemovalPreparationReceipt {
    NativeRemovalPreparationReceipt {
        workspace_commit: publication.workspace_commit,
        sources: publication.sources.keys().copied().collect(),
    }
}

#[cfg(test)]
thread_local! { static BEFORE_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default(); }

#[cfg(test)]
mod tests;
