//! Remove a revision's complete native body family while retaining independently
//! committed control metadata. Physical/key and other-copy completion is separate.

use super::*;

mod inventory;
#[cfg(test)]
mod tests;
mod verify;

pub(crate) const FEATURE: &str = "continuous-record-pruning-v1";
const OPERATION: &str = "record_prune";
const PREFIX: &[u8] = b"record-pruned/";
const MAX_PUBLICATION_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordPruningPublication {
    witness: NativeRecordRemovalWitnessReceipt,
    workspace_commit: u64,
    pub(crate) scopes: BTreeSet<String>,
    write_validations: BTreeMap<u64, RemovalCheckpoint>,
}

/// Logical revision-body cleanup, not deletion completion or key erasure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRecordPruningReceipt {
    /// Native workspace commit accepting the complete body-family removal.
    pub workspace_commit: u64,
    /// Independently retained removal witness used by this publication.
    pub witness: NativeRecordRemovalWitnessReceipt,
}

pub(crate) struct PrunedRecord {
    pub(crate) witness: RecordRemovalWitness,
    publication: RecordPruningPublication,
}

impl RecordPruningPublication {
    pub(crate) fn belongs_to_removal(&self, request: &NativeRemovalRequestReceipt) -> bool {
        // The verified witness and the supplied verified receipt share the same
        // unique position in the independently retained removal journal.
        self.witness.authority_id == request.authority_id
            && self.witness.removal_sequence == request.sequence
    }

    fn receipt(&self) -> NativeRecordPruningReceipt {
        NativeRecordPruningReceipt {
            workspace_commit: self.workspace_commit,
            witness: self.witness.clone(),
        }
    }

    fn request_digest(&self, workspace: &str) -> ServiceResult<String> {
        canonical_digest(&(FEATURE, workspace, &self.witness))
    }
}

impl PrunedRecord {
    pub(crate) fn check_write(
        &self,
        ledger: &NativeSuppressionLedger,
        event: &StoredEvent,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let checkpoint = self
            .publication
            .write_validations
            .get(&event.global_commit)
            .ok_or_else(|| integrity("pruned source-aware group has no retained validation"))?;
        ledger.check_record_write_validation(checkpoint, event, budget)
    }
}

impl NativeService {
    /// Erase exactly one revision's primary projection and all accepted birth/
    /// closure copies in one Sync. Admin plus the revision policy remain required.
    /// The retained witness must cover the current revision. Original receipts,
    /// hashed identity reservation and disclosure barriers remain unchanged.
    pub fn prune_record_revision(
        &self,
        context: &AuthenticatedRequestContext,
        witness_receipt: &NativeRecordRemovalWitnessReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRecordPruningReceipt> {
        require_capability(context, Capability::Admin)?;
        budget.check().map_err(raw_index::budget_error)?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("record pruning requires retained authority"))?;
        let witness = ledger.read_record_removal_witness(witness_receipt, budget)?;
        let policy = witness.policy();
        let mut access = policy.access.clone();
        access.retrievable = true;
        if !policy_allows(&context.request, &access) {
            return Err(permission_denied());
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let world = self.recovery_workspace(&snapshot, &workspace, budget)?;
        if let Some(pruned) =
            self.pruned_record(&snapshot, &policy.record_digest, policy.revision, budget)?
        {
            if pruned.witness != witness {
                return Err(integrity(
                    "record pruning retry changes its revision witness",
                ));
            }
            return Ok(pruned.publication.receipt());
        }
        let policy_bytes = read_bytes(
            &snapshot,
            &self.keyspaces.policy_history,
            &history_key(&policy.record_digest, policy.revision),
            MAX_BYTES,
            budget,
        )?;
        if decode::<StoredPolicy>(&policy_bytes, "record pruning current policy")? != *policy {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "record changed after its removal witness",
                true,
            ));
        }
        self.require_record_pruning_absent(&snapshot, &workspace, policy, &world, budget)?;
        if self.record_removal_witness(&snapshot, policy, budget)? != witness {
            return Err(integrity(
                "record pruning bytes differ from independent witness",
            ));
        }
        let write_validations = self.retain_record_write_validations(
            &snapshot,
            context,
            witness_receipt,
            policy,
            budget,
        )?;
        #[cfg(test)]
        BEFORE_PRUNING.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if let Some(pruned) =
            self.pruned_record(&tx, &policy.record_digest, policy.revision, budget)?
        {
            if pruned.witness != witness {
                return Err(integrity(
                    "record pruning retry changes its revision witness",
                ));
            }
            return Ok(pruned.publication.receipt());
        }
        if self.workspace_state(&tx, &context.request.workspace_id)? != world {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "workspace changed before record pruning",
                true,
            ));
        }
        let frame = self.begin_frame(&tx, &context.request.workspace_id, false)?;
        let publication = RecordPruningPublication {
            witness: witness_receipt.clone(),
            workspace_commit: frame.state.watermarks.journal,
            scopes: policy.access.scopes.clone(),
            write_validations,
        };
        let marker_bytes = encode(&publication)?;
        budget
            .charge(1, marker_bytes.len() as u64)
            .map_err(raw_index::budget_error)?;
        if marker_bytes.len() > MAX_PUBLICATION_BYTES {
            return Err(exhausted("record pruning metadata exceeds its bound"));
        }
        for control in witness.controls() {
            let mutation = control
                .policy
                .transaction_to
                .unwrap_or(control.policy.transaction_from);
            tx.delete(
                &self.keyspaces.continuous,
                mutation_address(mutation, &policy.record_digest, policy.revision),
            )
            .map_err(storage_error)?;
        }
        tx.delete(
            &self.keyspaces.content_history,
            history_key(&policy.record_digest, policy.revision),
        )
        .map_err(storage_error)?;
        tx.put(
            &self.keyspaces.continuous,
            pruned_key(&policy.record_digest, policy.revision),
            marker_bytes,
        )
        .map_err(storage_error)?;
        for scope in &publication.scopes {
            tx.put(
                &self.keyspaces.continuous,
                capture::scope_key(&workspace, scope),
                encode(&frame.state.watermarks.journal)?,
            )
            .map_err(storage_error)?;
        }
        self.enable_capture_extension(&mut tx, FEATURE)?;
        let request = publication.request_digest(&workspace)?;
        self.finish_frame(
            &mut tx,
            &frame,
            OPERATION,
            request.as_bytes(),
            &request,
            &publication,
        )?;
        budget.check().map_err(raw_index::budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        #[cfg(test)]
        AFTER_PRUNING.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        budget.check().map_err(raw_index::budget_error)?;
        Ok(publication.receipt())
    }

    fn require_record_pruning_absent<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        policy: &StoredPolicy,
        world: &WorkspaceState,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let birth = self.recovery_global_event(snapshot, policy.transaction_from, budget)?;
        for commit in birth.workspace_commit..world.watermarks.journal {
            let (_, event) = self.recovery_event(snapshot, workspace, commit + 1, budget)?;
            if let Some(publication) = declaration(&event)?
                && publication.witness.record_digest == policy.record_digest
                && publication.witness.revision == policy.revision
            {
                return Err(integrity("accepted record pruning lost its marker"));
            }
        }
        Ok(())
    }
}

fn declaration(event: &StoredEvent) -> ServiceResult<Option<&RecordPruningPublication>> {
    if event.operation != OPERATION {
        if event.accepted_record_pruning.is_some() {
            return Err(integrity("record pruning has an invalid journal owner"));
        }
        return Ok(None);
    }
    let publication = event
        .accepted_record_pruning
        .as_ref()
        .ok_or_else(|| integrity("record pruning declaration absent"))?;
    if publication.workspace_commit != event.workspace_commit
        || publication.write_validations.len() > 2
        || publication.witness.mutation_commit >= event.global_commit
        || !event.accepted_records.is_empty()
        || event.event_digest != event_digest(event)?
        || event.request_digest != publication.request_digest(&event.workspace_digest)?
        || event.response_digest != canonical_digest(publication)?
    {
        return Err(integrity(
            "record pruning declaration differs from its acceptance",
        ));
    }
    Ok(Some(publication))
}

pub(crate) fn mutation_identity(global: u64, key: &[u8]) -> ServiceResult<(&str, u32)> {
    let text = std::str::from_utf8(key).map_err(|_| integrity("record mutation key is invalid"))?;
    let suffix = text
        .strip_prefix(&mutation_prefix(global))
        .ok_or_else(|| integrity("record mutation prefix differs"))?;
    let (record, revision) = suffix
        .split_once('/')
        .ok_or_else(|| integrity("record mutation revision absent"))?;
    let revision: u32 = revision
        .parse()
        .map_err(|_| integrity("record mutation revision invalid"))?;
    if revision == 0
        || blake3::Hash::from_hex(record).is_err()
        || mutation_address(global, record, revision) != key
    {
        return Err(integrity("record mutation identity is invalid"));
    }
    Ok((record, revision))
}

pub(super) fn mutation_address(global: u64, record: &str, revision: u32) -> Vec<u8> {
    format!("{}{record}/{revision:010}", mutation_prefix(global)).into_bytes()
}
fn pruned_key(record: &str, revision: u32) -> Vec<u8> {
    format!("record-pruned/{record}/{revision:010}").into_bytes()
}

#[cfg(test)]
thread_local! {
    static BEFORE_PRUNING: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
    static AFTER_PRUNING: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
}
