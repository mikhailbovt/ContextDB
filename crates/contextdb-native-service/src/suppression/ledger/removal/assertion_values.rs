//! Exact value classifications retained before a mixed batch loses old bytes.

use super::*;
use crate::assertions::retention::witness::values::{
    AttestedAssertionValues, MAX_VALUE_WITNESS_BYTES,
};
use crate::{NativeAssertionValueWitnessReceipt, NativeCustodyKeys};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AssertionValuesDeclaration {
    workspace: String,
    request: RemovalCheckpoint,
    assertion_commit: u64,
    pruning_commit: u64,
    classification_digest: String,
    witness_digest: String,
}

impl AssertionValuesDeclaration {
    pub(super) fn validate(&self, sequence: u64) -> ServiceResult<()> {
        for digest in [
            &self.workspace,
            &self.request.digest,
            &self.classification_digest,
            &self.witness_digest,
        ] {
            valid_digest(digest)?;
        }
        if self.request.sequence == 0
            || self.request.sequence >= sequence
            || self.assertion_commit == 0
            || self.pruning_commit <= self.assertion_commit
        {
            return Err(integrity("assertion value witness declaration differs"));
        }
        Ok(())
    }

    pub(super) fn key(&self) -> Vec<u8> {
        format!(
            "removal/assertion-values/{}/{:020}/{}",
            self.workspace, self.request.sequence, self.classification_digest
        )
        .into_bytes()
    }
}

impl NativeSuppressionLedger {
    // Complete bounded journal scan; logical commit numbers can repeat after
    // restore, so the caller also matches exact ownership and custody identities.
    pub(crate) fn assertion_value_history(
        &self,
        workspace_id: &str,
        assertion_commit: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(
        RemovalCheckpoint,
        Vec<(NativeAssertionValueWitnessReceipt, AttestedAssertionValues)>,
    )> {
        let workspace = digest_bytes(workspace_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let head = self.removal_global_head(&snapshot)?;
        let mut previous = genesis(&self.identity)?;
        let mut found = Vec::new();
        for sequence in 1..=head.sequence {
            let event = self.budgeted_removal_event(&snapshot, sequence, budget)?;
            if event.previous != previous.digest {
                return Err(integrity("assertion value history is discontinuous"));
            }
            if let Operation::AssertionValues {
                witness: declaration,
            } = &event.operation
                && declaration.workspace == workspace
                && declaration.assertion_commit == assertion_commit
            {
                if found.len() == 256 {
                    return Err(exhausted("assertion value history exceeds 256 witnesses"));
                }
                let witness = self.load_assertion_values(
                    &snapshot,
                    &event.checkpoint(),
                    declaration,
                    budget,
                )?;
                let locator = snapshot
                    .get(&self.rows, &declaration.key())
                    .map_err(storage_error)?;
                budget
                    .charge(1, locator.as_ref().map_or(0, |bytes| bytes.len() as u64))
                    .map_err(budget_error)?;
                if locator != Some(encode(&event.checkpoint())?) {
                    return Err(integrity("assertion value history locator differs"));
                }
                found.push((value_receipt(self, &event.checkpoint()), witness));
            }
            previous = event.checkpoint();
        }
        let tail = snapshot
            .scan_prefix_page(
                &self.rows,
                ScanPageRequest {
                    prefix: b"removal/event/",
                    start_after: Some(&event_key(head.sequence)),
                    max_entries: 1,
                    max_bytes: 1024 * 1024,
                },
            )
            .map_err(storage_error)?;
        for row in &tail.entries {
            budget
                .charge(1, (row.key.len() + row.value.len()) as u64)
                .map_err(budget_error)?;
        }
        if previous != head || !tail.entries.is_empty() || tail.continuation.is_some() {
            return Err(integrity("assertion value history terminal differs"));
        }
        let latest = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if self.removal_global_head(&latest)? != head {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "assertion value history changed; retry inventory",
                true,
            ));
        }
        budget.check().map_err(budget_error)?;
        Ok((head, found))
    }

    pub(crate) fn retain_assertion_value_witness(
        &self,
        request: &RemovalCheckpoint,
        witness: &AttestedAssertionValues,
        keys: &NativeCustodyKeys,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeAssertionValueWitnessReceipt> {
        witness.verify(keys)?;
        let bytes = encode(witness)?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_VALUE_WITNESS_BYTES {
            return Err(exhausted("assertion value witness exceeds 1 MiB"));
        }
        let body = &witness.body;
        let declaration = AssertionValuesDeclaration {
            workspace: digest_bytes(body.workspace_id.as_bytes()),
            request: request.clone(),
            assertion_commit: body.owner.assertion_commit,
            pruning_commit: body.pruning_commit,
            classification_digest: canonical_digest(body)?,
            witness_digest: digest_bytes(&bytes),
        };
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        self.validate_assertion_value_owner(&tx, &declaration, witness, budget)?;
        if let Some((checkpoint, operation)) = self.find_retained_control(
            &tx,
            &declaration.workspace,
            request,
            &declaration.key(),
            budget,
        )? {
            let Operation::AssertionValues { witness: prior } = operation else {
                return Err(integrity("assertion values locator has another operation"));
            };
            let retained = self.load_assertion_values(&tx, &checkpoint, &prior, budget)?;
            retained.verify(keys)?;
            // A retry may have a fresh nonce, but may not change any classification.
            if retained.body != witness.body {
                return Err(ServiceError::new(
                    ErrorCode::IdempotencyConflict,
                    "assertion pruning already has different value ownership",
                    false,
                ));
            }
            return Ok(value_receipt(self, &checkpoint));
        }
        let accepted = self.append_removal_event(
            &mut tx,
            Operation::AssertionValues {
                witness: declaration.clone(),
            },
        )?;
        tx.put(&self.rows, declaration.key(), encode(&accepted)?)
            .map_err(storage_error)?;
        tx.put(&self.rows, blob_key(accepted.sequence), bytes)
            .map_err(storage_error)?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(value_receipt(self, &accepted))
    }

    // This returns authenticated removal-journal acceptance. Callers must also
    // verify the separate custody attestation before using semantic classifications.
    pub(crate) fn read_assertion_value_witness(
        &self,
        receipt: &NativeAssertionValueWitnessReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AttestedAssertionValues> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let event = self.budgeted_removal_event(&snapshot, receipt.witness_sequence, budget)?;
        let checkpoint = event.checkpoint();
        let operation = event.operation;
        let Operation::AssertionValues {
            witness: declaration,
        } = operation
        else {
            return Err(integrity(
                "assertion value publication has another operation",
            ));
        };
        if *receipt != value_receipt(self, &checkpoint)
            || self.find_retained_control(
                &snapshot,
                &declaration.workspace,
                &declaration.request,
                &declaration.key(),
                budget,
            )? != Some((
                checkpoint.clone(),
                Operation::AssertionValues {
                    witness: declaration.clone(),
                },
            ))
        {
            return Err(integrity(
                "assertion value receipt or retained acceptance differs",
            ));
        }
        self.load_assertion_values(&snapshot, &checkpoint, &declaration, budget)
    }

    fn validate_assertion_value_owner<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        declaration: &AssertionValuesDeclaration,
        witness: &AttestedAssertionValues,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let body = &witness.body;
        let event = self.budgeted_removal_event(snapshot, declaration.request.sequence, budget)?;
        if event.checkpoint() != declaration.request
            || !matches!(event.operation, Operation::Request { ref intent, .. } if intent.workspace == declaration.workspace)
            || body.owner.authority_id != self.authority_id()
            || body.owner.removal_sequence != declaration.request.sequence
            || body.owner.assertion_commit != declaration.assertion_commit
            || body.pruning_commit != declaration.pruning_commit
            || digest_bytes(body.workspace_id.as_bytes()) != declaration.workspace
            || canonical_digest(body)? != declaration.classification_digest
            || witness.proof.len() != 104
        {
            return Err(integrity(
                "assertion value witness request or acceptance differs",
            ));
        }
        let (owner, _) = self.read_assertion_removal_witness(&body.owner, budget)?;
        body.validate(&owner)
    }

    fn load_assertion_values<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        checkpoint: &RemovalCheckpoint,
        declaration: &AssertionValuesDeclaration,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AttestedAssertionValues> {
        let bytes = snapshot
            .get(&self.rows, &blob_key(checkpoint.sequence))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("independent assertion value witness is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_VALUE_WITNESS_BYTES
            || digest_bytes(&bytes) != declaration.witness_digest
        {
            return Err(integrity(
                "assertion value witness differs from accepted commitment",
            ));
        }
        let witness: AttestedAssertionValues = decode(&bytes, "assertion value witness")?;
        if witness.body.owner.witness_sequence >= checkpoint.sequence {
            return Err(integrity(
                "assertion value witness precedes its source ownership",
            ));
        }
        self.validate_assertion_value_owner(snapshot, declaration, &witness, budget)?;
        Ok(witness)
    }

    pub(super) fn verify_assertion_value_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &Event,
        declaration: &AssertionValuesDeclaration,
        expected: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ServiceResult<()> {
        let witness = self.load_assertion_values(
            snapshot,
            &event.checkpoint(),
            declaration,
            &mut inventory::verification_budget(),
        )?;
        if expected
            .insert(declaration.key(), encode(&event.checkpoint())?)
            .is_some()
        {
            return Err(integrity(
                "assertion value witness repeats a pruning identity",
            ));
        }
        expected.insert(blob_key(event.sequence), encode(&witness)?);
        Ok(())
    }
}

fn blob_key(sequence: u64) -> Vec<u8> {
    format!("removal/assertion-values-blob/{sequence:020}").into_bytes()
}
fn value_receipt(
    ledger: &NativeSuppressionLedger,
    checkpoint: &RemovalCheckpoint,
) -> NativeAssertionValueWitnessReceipt {
    NativeAssertionValueWitnessReceipt {
        authority_id: ledger.authority_id(),
        witness_sequence: checkpoint.sequence,
        digest: checkpoint.digest.clone(),
    }
}
