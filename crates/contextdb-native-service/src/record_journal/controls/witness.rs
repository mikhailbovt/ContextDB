//! Independently retained witnesses for future generic-record pruning.
//! This operation preserves every native body and does not complete removal.

use contextdb_core::ObservationId;
use contextdb_recall::QueryBudget;

use super::*;
use crate::suppression::{RecordSourceControl, RemovalCheckpoint};

mod graph;
#[cfg(test)]
pub(crate) mod tests;

pub(crate) const MAX_WITNESS_BYTES: usize = 2 * MAX_BYTES + 16 * 1024;

/// An independently retained witness, not a body-erasure or completion receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRecordRemovalWitnessReceipt {
    /// Current authority retained outside native backups.
    pub authority_id: uuid::Uuid,
    /// Accepted removal request requiring this record's source to be erased.
    pub removal_sequence: u64,
    /// Publication in the independent removal journal.
    pub witness_sequence: u64,
    /// Exact accepted witness publication commitment.
    pub digest: String,
    /// Hashed logical record identity.
    pub record_digest: String,
    /// Exact revision whose birth and optional closure were inspected.
    pub revision: u32,
    /// Last accepted mutation of this revision, in the native global journal.
    pub mutation_commit: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordRemovalWitness {
    version: u16,
    birth: RecordControl,
    closure: Option<RecordControl>,
    graph: graph::GraphControl,
}

impl RecordRemovalWitness {
    pub(crate) fn policy(&self) -> &StoredPolicy {
        &self.closure.as_ref().unwrap_or(&self.birth).policy
    }

    pub(crate) fn validate(&self, origin: &RecordSourceControl) -> ServiceResult<()> {
        self.birth.validate()?;
        let birth = &self.birth.policy;
        if self.version != 1
            || birth.transaction_to.is_some()
            || birth.record_digest != origin.record_digest
            || birth.revision != origin.revision
            || birth.transaction_from != origin.transaction_from
            || birth.content_digest != origin.birth_digest
            || self.birth.document_digest != origin.document_digest
            || birth.access.scopes != origin.scopes
            || digest_bytes(birth.access.workspace_id.as_bytes()) != origin.workspace
        {
            return Err(integrity(
                "record removal witness differs from retained origin",
            ));
        }
        if let Some(closure) = &self.closure {
            closure.validate()?;
            let mut expected = self.birth.clone();
            expected.policy.transaction_to = closure.policy.transaction_to;
            expected.policy.content_digest = closure.policy.content_digest.clone();
            if closure.policy.transaction_to.is_none() || expected != *closure {
                return Err(integrity(
                    "record witness closure changes its original revision",
                ));
            }
        }
        self.graph.validate(&self.birth)?;
        Ok(())
    }
}

impl NativeService {
    /// Retain one classified revision's complete pruning witness outside native
    /// restore. Admin and revision access remain required. A non-retrievable
    /// label may be inspected for this accepted removal, without disclosure.
    /// `removed_source` must belong to both the retained origin and request.
    /// Older full mutations must first use `prepare_record_controls`.
    /// A workspace CAS precedes the independent Sync; exact retries preserve its
    /// receipt. No native body, policy, original receipt or read gate is changed.
    pub fn prepare_record_removal(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        record_id: &str,
        revision: u32,
        removed_source: ObservationId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRecordRemovalWitnessReceipt> {
        require_capability(context, Capability::Admin)?;
        validate_identifier(record_id, "record removal identity")?;
        budget.check().map_err(raw_index::budget_error)?;
        if revision == 0 {
            return Err(invalid("record removal requires a revision"));
        }
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("record removal requires retained authority"))?;
        if !ledger.supports_record_sources() || request.authority_id != ledger.authority_id() {
            return Err(invalid(
                "record removal requires the current version 3 authority",
            ));
        }
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let checkpoint = RemovalCheckpoint {
            sequence: request.sequence,
            digest: request.digest.clone(),
        };
        let intent = ledger.retained_removal_intent(&workspace, &checkpoint)?;
        if retention::removal_receipt(ledger, &checkpoint, &intent) != *request {
            return Err(invalid("record removal request receipt differs"));
        }
        let record_digest = digest_bytes(record_id.as_bytes());
        let origin = ledger
            .retained_record_sources(&workspace, &record_digest, revision)?
            .ok_or_else(|| {
                ServiceError::new(
                    ErrorCode::EvidenceRequired,
                    "record removal requires classified origins",
                    false,
                )
            })?;
        let source = ledger.removal_source(&workspace, &checkpoint, removed_source, budget)?;
        if origin.record_control()?.sources.get(&removed_source) != Some(&source.control_digest) {
            return Err(invalid("record is not derived from this removal source"));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let world = self.recovery_workspace(&snapshot, &workspace, budget)?;
        let policy: StoredPolicy = decode(
            &read_bytes(
                &snapshot,
                &self.keyspaces.policy_history,
                &history_key(&record_digest, revision),
                MAX_BYTES,
                budget,
            )?,
            "record removal policy",
        )?;
        validate_stored_policy(&policy)?;
        if policy.record_digest != record_digest || policy.revision != revision {
            return Err(integrity("record removal policy identity differs"));
        }
        let mut access = policy.access.clone();
        access.retrievable = true;
        if !policy_allows(&context.request, &access) {
            return Err(permission_denied());
        }
        let witness = self.record_removal_witness(&snapshot, &policy, budget)?;
        witness.validate(origin.record_control()?)?;
        #[cfg(test)]
        BEFORE_PUBLICATION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let latest = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if self.workspace_state(&latest, &context.request.workspace_id)? != world {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "workspace changed while retaining record removal witness",
                true,
            ));
        }
        let accepted = ledger.retain_record_removal_witness(
            &checkpoint,
            removed_source,
            &origin,
            &witness,
            budget,
        )?;
        #[cfg(test)]
        AFTER_AUTHORITY_SYNC.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        budget.check().map_err(raw_index::budget_error)?;
        Ok(NativeRecordRemovalWitnessReceipt {
            authority_id: ledger.authority_id(),
            removal_sequence: checkpoint.sequence,
            witness_sequence: accepted.sequence,
            digest: accepted.digest,
            record_digest,
            revision,
            mutation_commit: policy.transaction_to.unwrap_or(policy.transaction_from),
        })
    }

    fn record_removal_witness<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        policy: &StoredPolicy,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RecordRemovalWitness> {
        let current_bytes = read_bytes(
            snapshot,
            &self.keyspaces.content_history,
            &history_key(&policy.record_digest, policy.revision),
            MAX_BYTES,
            budget,
        )?;
        let current_record = self.decode_content(&current_bytes, policy)?;
        let (birth, original) =
            self.removal_mutation_control(snapshot, policy, policy.transaction_from, budget)?;
        if original.document != current_record.document || original.transaction_to.is_some() {
            return Err(integrity(
                "record removal original differs from current revision",
            ));
        }
        let closure = if let Some(global) = policy.transaction_to {
            let (control, record) =
                self.removal_mutation_control(snapshot, policy, global, budget)?;
            if record != current_record {
                return Err(integrity("record removal closure differs from projection"));
            }
            Some(control)
        } else {
            if original != current_record {
                return Err(integrity("record removal birth differs from projection"));
            }
            None
        };
        Ok(RecordRemovalWitness {
            version: 1,
            birth,
            closure,
            graph: graph::GraphControl::from_document(&original.document)?,
        })
    }

    fn removal_mutation_control<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        policy: &StoredPolicy,
        global: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(RecordControl, MemoryRecord)> {
        let event = self.recovery_global_event(snapshot, global, budget)?;
        let (_, mapped) = self.recovery_event(
            snapshot,
            &event.workspace_digest,
            event.workspace_commit,
            budget,
        )?;
        if event != mapped
            || event.workspace_digest != digest_bytes(policy.access.workspace_id.as_bytes())
        {
            return Err(integrity(
                "record removal mutation has no exact workspace mapping",
            ));
        }
        let key = format!(
            "{}{}/{:010}",
            mutation_prefix(global),
            policy.record_digest,
            policy.revision
        )
        .into_bytes();
        let references: Vec<_> = event
            .accepted_records
            .iter()
            .filter(|reference| reference.key == key)
            .collect();
        if references.len() != 1 {
            return Err(integrity("record removal mutation lacks exact acceptance"));
        }
        let reference = references[0];
        let bytes = read_bytes(
            snapshot,
            &self.keyspaces.continuous,
            &key,
            MAX_BYTES,
            budget,
        )?;
        if digest_bytes(&bytes) != reference.digest {
            return Err(integrity("record removal mutation digest differs"));
        }
        let record: MemoryRecord = decode(&bytes, "record removal mutation")?;
        let control = match self.budgeted_record_mutation_control(
            snapshot,
            &event,
            reference,
            self.record_control_activation(snapshot)?,
            Some(budget),
        )? {
            Some(control) => control,
            None => self
                .prepared_record_controls(snapshot, &event, budget)?
                .remove(&key)
                .ok_or_else(|| {
                    integrity("record removal requires an explicitly prepared control")
                })?,
        };
        control.validate_binding(&event, reference)?;
        if control != RecordControl::from_record(&record)? {
            return Err(integrity(
                "record removal control differs from accepted body",
            ));
        }
        Ok((control, record))
    }
}

fn read_bytes<S: ReadSnapshot>(
    snapshot: &S,
    space: &Keyspace,
    key: &[u8],
    max: usize,
    budget: &mut QueryBudget,
) -> ServiceResult<Vec<u8>> {
    let bytes = snapshot
        .get(space, key)
        .map_err(storage_error)?
        .ok_or_else(|| integrity("record removal row absent"))?;
    budget
        .charge(1, bytes.len() as u64)
        .map_err(raw_index::budget_error)?;
    if bytes.len() > max {
        return Err(exhausted("record removal row exceeds its bound"));
    }
    Ok(bytes)
}

#[cfg(test)]
thread_local! {
    static BEFORE_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
    static AFTER_AUTHORITY_SYNC: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
}
