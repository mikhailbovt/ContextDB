//! Independently retain a mixed batch's source ownership without its values.

use super::*;
use crate::{NativeRemovalRequestReceipt, policy_allows};

mod keys;
pub use keys::{NativeAssertionBatchKind, NativeAssertionCopyKind, NativeAssertionKeyInventory};
#[cfg(test)]
pub(crate) mod tests;

pub(crate) const MAX_WITNESS_BYTES: usize = MAX_STATE_BYTES + 1024 * 1024;

/// Independent assertion ownership evidence, not an erasure or admission receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAssertionRemovalWitnessReceipt {
    /// Current authority retained independently of native archives.
    pub authority_id: uuid::Uuid,
    /// Retained removal request selecting source-supported mutations.
    pub removal_sequence: u64,
    /// Exact publication in the independent removal journal.
    pub witness_sequence: u64,
    /// Commitment of that accepted witness publication.
    pub digest: String,
    /// Original workspace-local semantic publication.
    pub assertion_commit: u64,
    /// Scope required before administrative inspection.
    pub scope: ScopeId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssertionRemovalWitness {
    version: u16,
    receipt: AssertionReceipt,
    control: BatchControl,
    // None is an independently configured host policy, never a source assertion.
    mutations: Vec<Option<RemovedMutation>>,
}

impl AssertionRemovalWitness {
    fn from_batch(receipt: AssertionReceipt, batch: &RetainedAssertions) -> ServiceResult<Self> {
        Ok(Self {
            version: 1,
            receipt,
            control: batch.control.clone(),
            mutations: batch
                .mutations
                .iter()
                .map(|mutation| match mutation {
                    RetainedMutation::Live {
                        mutation: AssertionMutation::Policy { .. },
                    } => Ok(None),
                    RetainedMutation::Live { mutation } => {
                        RemovedMutation::from_mutation(mutation).map(Some)
                    }
                    RetainedMutation::Removed { control, .. } => Ok(Some(control.clone())),
                })
                .collect::<ServiceResult<_>>()?,
        })
    }

    pub(crate) fn workspace(&self) -> &str {
        &self.control.workspace_id
    }

    pub(crate) fn assertion_commit(&self) -> u64 {
        self.control.commit
    }

    pub(crate) fn scope(&self) -> ScopeId {
        self.control.scope
    }

    pub(crate) fn validate(&self, database_digest: &str, workspace: &str) -> ServiceResult<()> {
        let control = &self.control;
        if self.version != 1
            || self.receipt.domain != DOMAIN
            || digest_bytes(self.receipt.database_id.as_bytes()) != database_digest
            || digest_bytes(control.workspace_id.as_bytes()) != workspace
            || self.receipt.workspace_commit != control.commit
            || control.commit == 0
            || control.access.workspace_id != control.workspace_id
            || control.access.scopes != BTreeSet::from([control.scope.to_string()])
            || control.coverage.publication != control.commit
            || control.coverage.through >= control.commit
            || control.coverage.complete_prefix
                != (control.coverage.through >= control.observed_scope_epoch)
            || control.coverage.pending.len() > MAX_WINDOW
            || control.coverage.gaps.len() > MAX_WINDOW
            || control.interpretations.len() > MAX_WINDOW
            || control.mutations.len() > 64
            || self.mutations.len() != control.mutations.len()
        {
            return Err(integrity("assertion witness publication fields differ"));
        }
        for digest in std::iter::once(&control.request_digest)
            .chain(std::iter::once(&control.pipeline_digest))
            .chain(&control.mutations)
        {
            if blake3::Hash::from_hex(digest).is_err() {
                return Err(integrity("assertion witness digest is invalid"));
            }
        }
        for (ordinal, mutation) in self.mutations.iter().enumerate() {
            if let Some(mutation) = mutation
                && (mutation.body_digest != control.mutations[ordinal]
                    || mutation.key.scope != control.scope
                    || !mutation.sources.contains(&mutation.origin)
                    || blake3::Hash::from_hex(&mutation.source_digest).is_err()
                    || mutation
                        .evidence
                        .values()
                        .any(|span| !mutation.sources.contains(&span.event_id)))
            {
                return Err(integrity("assertion witness mutation ownership differs"));
            }
        }
        Ok(())
    }

    pub(crate) fn selected(&self, sources: &BTreeSet<ObservationId>) -> BTreeSet<usize> {
        self.mutations
            .iter()
            .enumerate()
            .filter_map(|(ordinal, mutation)| {
                mutation
                    .as_ref()
                    .filter(|mutation| !mutation.sources.is_disjoint(sources))
                    .map(|_| ordinal)
            })
            .collect()
    }
}

impl NativeService {
    /// Verify a mixed semantic batch and retain its source/control commitments
    /// independently. Source values, envelopes and host policy bodies are omitted.
    /// The same witness can be prepared before or after logical pruning. Native
    /// semantic replay is administrative and budgeted; a workspace CAS precedes
    /// external Sync. No native body, original receipt or read gate is changed.
    pub fn prepare_assertion_removal(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        scope: ScopeId,
        assertion_commit: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeAssertionRemovalWitnessReceipt> {
        require_scope(context, scope, Capability::Admin)?;
        let ledger = self.suppression.as_ref().ok_or_else(|| {
            crate::unsupported("assertion witness requires retained removal authority")
        })?;
        if !ledger.supports_record_sources() || request.authority_id != ledger.authority_id() {
            return Err(invalid(
                "assertion witness requires the current version 3 authority",
            ));
        }
        let lineage = self.read_original_removal_inventory(context, request, budget)?;
        let sources = lineage
            .sources
            .iter()
            .map(|source| source.receipt.event_id)
            .collect();
        let checkpoint = RemovalCheckpoint {
            sequence: request.sequence,
            digest: request.digest.clone(),
        };
        let workspace = workspace(context);
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let world = self.recovery_workspace(&snapshot, &workspace, budget)?;
        let (global, _) = self.select_snapshot(
            &snapshot,
            &context.request.workspace_id,
            Some(assertion_commit),
        )?;
        let bytes = snapshot
            .get(&self.keyspaces.events, &global.to_be_bytes())
            .map_err(storage_error)?
            .ok_or_else(|| invalid("assertion witness publication is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        let event: crate::StoredEvent = decode(&bytes, "assertion witness publication")?;
        if event.operation != "assertions"
            || event.global_commit != global
            || event.workspace_commit != assertion_commit
            || event.workspace_digest != workspace
            || crate::event_digest(&event)? != event.event_digest
        {
            return Err(invalid(
                "selected publication is not this workspace's assertion batch",
            ));
        }
        // Complete semantic verification includes provenance, negative relations,
        // remaining bodies and exact pruned controls, not just this row's hash.
        self.verify_assertion_records_budget(&snapshot, budget)?;
        let bindings = self.assertion_pruning_bindings(&snapshot, budget)?;
        let (_, _, batch) = self.load_retained_assertions(
            &snapshot,
            &event,
            bindings.get(&(workspace.clone(), assertion_commit)),
            budget,
        )?;
        if batch.control.scope != scope || !policy_allows(&context.request, &batch.control.access) {
            return Err(crate::permission_denied());
        }
        let witness = AssertionRemovalWitness::from_batch(
            event
                .accepted_assertions
                .ok_or_else(|| integrity("assertion receipt absent"))?,
            &batch,
        )?;
        if witness.selected(&sources).is_empty() {
            return Err(invalid(
                "assertion batch has no source selected by this request",
            ));
        }
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
            return Err(stale("workspace changed while retaining assertion witness"));
        }
        let accepted = ledger.retain_assertion_removal_witness(&checkpoint, &witness, budget)?;
        #[cfg(test)]
        AFTER_AUTHORITY_SYNC.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        budget.check().map_err(budget_error)?;
        Ok(NativeAssertionRemovalWitnessReceipt {
            authority_id: ledger.authority_id(),
            removal_sequence: checkpoint.sequence,
            witness_sequence: accepted.sequence,
            digest: accepted.digest,
            assertion_commit,
            scope,
        })
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
    static AFTER_AUTHORITY_SYNC: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
}
