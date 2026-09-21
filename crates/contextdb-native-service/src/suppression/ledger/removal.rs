//! Durable retention intent, independent of any restorable native checkpoint.
//! The current request remains required after local cleanup and after restore.

use contextdb_service::CaptureReceipt;

use super::*;

mod assertion_values;
mod assertion_witness;
mod controls;
mod inventory;
mod owned_keys;
mod primary_keys;
mod raw_copies;
mod raw_inventory;
mod record_witness;
#[cfg(test)]
mod tests;

pub(super) const HEAD: &[u8] = b"removal/head";
const DOMAIN: &str = "contextdb/native-removal-authority/v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemovalCheckpoint {
    pub sequence: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemovalIntent {
    pub workspace: String,
    pub roots: Vec<CaptureReceipt>,
    pub native_commit: u64,
    pub lineage_digest: ContentDigest,
    pub retry_key: String,
    pub request_digest: String,
    pub previous: RemovalCheckpoint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Register {
        workspace: String,
    },
    Request {
        intent: RemovalIntent,
        source_pages: Vec<ContentDigest>,
        payload_pages: Vec<ContentDigest>,
    },
    RecordWitness {
        witness: record_witness::RecordWitnessDeclaration,
    },
    AssertionWitness {
        witness: assertion_witness::AssertionWitnessDeclaration,
    },
    AssertionValues {
        witness: assertion_values::AssertionValuesDeclaration,
    },
    RecordValidation {
        validation: record_witness::validation::RecordWriteValidation,
    },
    RawCopies {
        observation: raw_copies::RawCopyDeclaration,
    },
    RawIndexInventory {
        witness: raw_inventory::RawIndexDeclaration,
    },
    OwnedKeys {
        witness: owned_keys::OwnedKeyDeclaration,
    },
    PrimaryKeys {
        witness: primary_keys::PrimaryKeyDeclaration,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    sequence: u64,
    previous: String,
    operation: Operation,
    digest: String,
}

impl Event {
    fn checkpoint(&self) -> RemovalCheckpoint {
        RemovalCheckpoint {
            sequence: self.sequence,
            digest: self.digest.clone(),
        }
    }
}

pub(super) fn genesis(identity: &Identity) -> ServiceResult<RemovalCheckpoint> {
    Ok(RemovalCheckpoint {
        sequence: 0,
        digest: canonical_digest(&(DOMAIN, identity))?,
    })
}

impl NativeSuppressionLedger {
    // A caller holding custody publication authority can use this final check to
    // establish one consistent archive/allocation/use/classification snapshot.
    pub(crate) fn require_removal_frontier(
        &self,
        expected: &RemovalCheckpoint,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let current = self.removal_global_head(&snapshot)?;
        budget
            .charge(1, encode(&current)?.len() as u64)
            .map_err(budget_error)?;
        if current != *expected {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "removal classifications changed; restart archive inventory",
                true,
            ));
        }
        Ok(())
    }
    pub(crate) fn supports_removal(&self) -> bool {
        self.identity.version >= 2
    }

    pub(super) fn removal_denies<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        id: ObservationId,
    ) -> ServiceResult<bool> {
        Ok(snapshot
            .get(&self.rows, &denied_key(workspace, id))
            .map_err(storage_error)?
            .is_some())
    }

    pub(crate) fn removal_genesis(&self, workspace: &str) -> ServiceResult<RemovalCheckpoint> {
        Ok(RemovalCheckpoint {
            sequence: 0,
            digest: canonical_digest(&(DOMAIN, &self.identity, workspace))?,
        })
    }

    pub(crate) fn require_removal_authority(&self) -> ServiceResult<()> {
        if self.identity.version < 2 {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "retention removal requires explicit migration of the version 1 suppression authority",
                false,
            ));
        }
        Ok(())
    }

    // Called before a workspace's first native publication. Every v2 workspace
    // has a permanent zero head, so losing all request rows cannot become absence.
    pub(crate) fn register_removal_workspace(&self, workspace: &str) -> ServiceResult<()> {
        if self.identity.version == 1 {
            return Ok(());
        }
        valid_digest(workspace)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if self.removal_head(&snapshot, workspace)?.is_some() {
            return Ok(());
        }
        drop(snapshot);
        let budget = QueryBudget::new(
            64,
            1024 * 1024,
            std::time::Duration::from_secs(30),
            Default::default(),
        );
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if self.removal_head(&tx, workspace)?.is_some() {
            return Ok(());
        }
        self.append_removal_event(
            &mut tx,
            Operation::Register {
                workspace: workspace.into(),
            },
        )?;
        tx.put(
            &self.rows,
            current_key(workspace),
            encode(&self.removal_genesis(workspace)?)?,
        )
        .map_err(storage_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )
    }

    pub(crate) fn current_removal(
        &self,
        workspace: &str,
    ) -> ServiceResult<Option<RemovalCheckpoint>> {
        if self.identity.version == 1 {
            return Ok(None);
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.removal_head(&snapshot, workspace)
    }

    pub(crate) fn removal_request(
        &self,
        workspace: &str,
        retry_key: &str,
        request_digest: &str,
    ) -> ServiceResult<Option<(RemovalCheckpoint, RemovalIntent)>> {
        self.require_removal_authority()?;
        valid_digest(retry_key)?;
        valid_digest(request_digest)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.find_removal_request(&snapshot, workspace, retry_key, request_digest)
    }

    pub(crate) fn request_removal(
        &self,
        intent: RemovalIntent,
        inventory: &NativeDeletionLineage,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(RemovalCheckpoint, RemovalIntent)> {
        self.require_removal_authority()?;
        self.validate_removal_intent(&intent)?;
        self.validate_removal_inventory(&intent, inventory)?;
        let inventory_rows = inventory::rows(inventory, budget)?;
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if let Some(accepted) = self.find_removal_request(
            &tx,
            &intent.workspace,
            &intent.retry_key,
            &intent.request_digest,
        )? {
            return Ok(accepted);
        }
        if self.removal_head(&tx, &intent.workspace)?.as_ref() != Some(&intent.previous) {
            return Err(pending());
        }
        for (key, value) in inventory_rows {
            if let Some(previous) = tx.get(&self.rows, &key).map_err(storage_error)?
                && previous != value
            {
                return Err(integrity("retained removal inventory identity differs"));
            }
            tx.put(&self.rows, key, value).map_err(storage_error)?;
        }
        let checkpoint = self.append_removal_event(
            &mut tx,
            Operation::Request {
                intent: intent.clone(),
                source_pages: inventory::source_page_digests(inventory)?,
                payload_pages: inventory::payload_page_digests(inventory)?,
            },
        )?;
        tx.put(
            &self.rows,
            current_key(&intent.workspace),
            encode(&checkpoint)?,
        )
        .map_err(storage_error)?;
        tx.put(
            &self.rows,
            request_key(&intent.workspace, checkpoint.sequence),
            encode(&checkpoint)?,
        )
        .map_err(storage_error)?;
        tx.put(
            &self.rows,
            retry_key(&intent.workspace, &intent.retry_key),
            encode(&checkpoint)?,
        )
        .map_err(storage_error)?;
        for source in &inventory.sources {
            let key = denied_key(&intent.workspace, source.receipt.event_id);
            if let Some(bytes) = tx.get(&self.rows, &key).map_err(storage_error)?
                && decode::<ContentDigest>(&bytes, "retention source identity")?
                    != source.receipt.event_digest
            {
                return Err(integrity("retention source identity was reused"));
            }
            tx.put(&self.rows, key, encode(&source.receipt.event_digest)?)
                .map_err(storage_error)?;
        }
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok((checkpoint, intent))
    }

    pub(crate) fn retained_removal_inventory(
        &self,
        workspace: &str,
        checkpoint: &RemovalCheckpoint,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(RemovalIntent, NativeDeletionLineage)> {
        self.require_removal_authority()?;
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let global = self.removal_global_head(&snapshot)?;
        if checkpoint.sequence == 0 || checkpoint.sequence > global.sequence {
            return Err(invalid("removal request is outside the retained authority"));
        }
        let event = self.read_removal_event(&snapshot, checkpoint.sequence)?;
        if event.checkpoint() != *checkpoint {
            return Err(invalid("removal request commitment differs"));
        }
        let Operation::Request { intent, .. } = event.operation else {
            return Err(invalid("retention registration is not a removal request"));
        };
        if intent.workspace != workspace {
            return Err(permission_denied());
        }
        let indexed: RemovalCheckpoint = decode(
            &snapshot
                .get(&self.rows, &request_key(workspace, checkpoint.sequence))
                .map_err(storage_error)?
                .ok_or_else(|| integrity("retained removal request index is missing"))?,
            "retained removal request index",
        )?;
        if indexed != *checkpoint {
            return Err(integrity("retained removal request index differs"));
        }
        let inventory = self.read_removal_inventory(&snapshot, &intent, budget)?;
        Ok((intent, inventory))
    }

    pub(crate) fn retained_removal_intent(
        &self,
        workspace: &str,
        checkpoint: &RemovalCheckpoint,
    ) -> ServiceResult<RemovalIntent> {
        self.require_removal_authority()?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if checkpoint.sequence == 0
            || checkpoint.sequence > self.removal_global_head(&snapshot)?.sequence
        {
            return Err(invalid("removal request is outside the retained authority"));
        }
        let event = self.read_removal_event(&snapshot, checkpoint.sequence)?;
        if event.checkpoint() != *checkpoint {
            return Err(invalid("removal request commitment differs"));
        }
        let Operation::Request { intent, .. } = event.operation else {
            return Err(invalid("retention registration is not a request"));
        };
        if intent.workspace != workspace {
            return Err(permission_denied());
        }
        Ok(intent)
    }

    fn append_removal_event<T: WriteTransaction>(
        &self,
        tx: &mut T,
        operation: Operation,
    ) -> ServiceResult<RemovalCheckpoint> {
        let head = self.removal_global_head(tx)?;
        let mut event = Event {
            sequence: head
                .sequence
                .checked_add(1)
                .ok_or_else(|| exhausted("retention sequence overflow"))?,
            previous: head.digest,
            operation,
            digest: String::new(),
        };
        event.digest = canonical_digest(&(DOMAIN, &self.identity, &event))?;
        let checkpoint = event.checkpoint();
        tx.put(&self.rows, event_key(event.sequence), encode(&event)?)
            .map_err(storage_error)?;
        tx.put(&self.rows, HEAD.to_vec(), encode(&checkpoint)?)
            .map_err(storage_error)?;
        Ok(checkpoint)
    }

    fn removal_global_head<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<RemovalCheckpoint> {
        let head: RemovalCheckpoint = decode(
            &snapshot
                .get(&self.rows, HEAD)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("retention authority head is missing"))?,
            "retention head",
        )?;
        valid_digest(&head.digest)?;
        if head.sequence == 0 && head != genesis(&self.identity)? {
            return Err(integrity("retention genesis differs"));
        }
        Ok(head)
    }

    fn removal_head<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
    ) -> ServiceResult<Option<RemovalCheckpoint>> {
        let global = self.removal_global_head(snapshot)?;
        let Some(bytes) = snapshot
            .get(&self.rows, &current_key(workspace))
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        let head: RemovalCheckpoint = decode(&bytes, "workspace retention head")?;
        if head.sequence == 0 {
            if head != self.removal_genesis(workspace)? {
                return Err(integrity("workspace retention genesis differs"));
            }
        } else if head.sequence > global.sequence {
            return Err(integrity("workspace retention exceeds authority"));
        } else {
            let event = self.read_removal_event(snapshot, head.sequence)?;
            if event.checkpoint() != head
                || !matches!(&event.operation,
                Operation::Request { intent, .. } if intent.workspace == workspace)
            {
                return Err(integrity(
                    "workspace retention head lacks its accepted request",
                ));
            }
        }
        Ok(Some(head))
    }

    fn read_removal_event<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        sequence: u64,
    ) -> ServiceResult<Event> {
        let bytes = snapshot
            .get(&self.rows, &event_key(sequence))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("retention authority event is missing"))?;
        self.decode_removal_event(&bytes, sequence)
    }

    fn decode_removal_event(&self, bytes: &[u8], sequence: u64) -> ServiceResult<Event> {
        let event: Event = decode(bytes, "retention event")?;
        let mut unsigned = event.clone();
        unsigned.digest.clear();
        if sequence == 0
            || event.sequence != sequence
            || event.digest != canonical_digest(&(DOMAIN, &self.identity, &unsigned))?
        {
            return Err(integrity("retention event binding differs"));
        }
        match &event.operation {
            Operation::Register { workspace } => valid_digest(workspace)?,
            Operation::RecordWitness { witness } => witness.validate(sequence)?,
            Operation::AssertionWitness { witness } => witness.validate(sequence)?,
            Operation::AssertionValues { witness } => witness.validate(sequence)?,
            Operation::RecordValidation { validation } => validation.validate(sequence)?,
            Operation::RawCopies { observation } => observation.validate()?,
            Operation::RawIndexInventory { witness } => witness.validate(sequence)?,
            Operation::PrimaryKeys { witness } => witness.validate(sequence)?,
            Operation::OwnedKeys { witness } => witness.validate(sequence)?,
            Operation::Request {
                intent,
                source_pages,
                payload_pages,
            } => {
                self.validate_removal_intent(intent)?;
                if source_pages.is_empty() || source_pages.len() > 256 || payload_pages.len() > 256
                {
                    return Err(integrity("retained source page manifest is invalid"));
                }
            }
        }
        Ok(event)
    }

    fn find_removal_request<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        retry: &str,
        request_digest: &str,
    ) -> ServiceResult<Option<(RemovalCheckpoint, RemovalIntent)>> {
        let Some(bytes) = snapshot
            .get(&self.rows, &retry_key(workspace, retry))
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        let checkpoint: RemovalCheckpoint = decode(&bytes, "retention retry")?;
        let event = self.read_removal_event(snapshot, checkpoint.sequence)?;
        if event.checkpoint() != checkpoint {
            return Err(integrity("retention retry checkpoint differs"));
        }
        let Operation::Request { intent, .. } = event.operation else {
            return Err(integrity("retention retry is not a request"));
        };
        if intent.workspace != workspace || intent.retry_key != retry {
            return Err(integrity("retention retry identity differs"));
        }
        if intent.request_digest != request_digest {
            return Err(ServiceError::new(
                ErrorCode::IdempotencyConflict,
                "retention request retry conflicts",
                false,
            ));
        }
        Ok(Some((checkpoint, intent)))
    }

    fn validate_removal_intent(&self, intent: &RemovalIntent) -> ServiceResult<()> {
        valid_digest(&intent.workspace)?;
        valid_digest(&intent.retry_key)?;
        valid_digest(&intent.request_digest)?;
        valid_digest(&intent.previous.digest)?;
        let ids: BTreeSet<_> = intent.roots.iter().map(|root| root.event_id).collect();
        if !(1..=256).contains(&intent.roots.len())
            || ids.len() != intent.roots.len()
            || intent.native_commit == 0
            || encode(intent)?.len() > 512 * 1024
            || intent.roots.iter().any(|root| {
                root.domain != contextdb_service::NATIVE_CAPTURE_DOMAIN
                    || digest_bytes(root.database_id.as_bytes()) != self.identity.database
                    || digest_bytes(root.workspace_id.to_string().as_bytes()) != intent.workspace
                    || root.workspace_commit == 0
                    || root.workspace_commit > intent.native_commit
            })
        {
            return Err(integrity("retention intent source identities are invalid"));
        }
        Ok(())
    }

    pub(super) fn verify_removal_ledger<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        expected: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ServiceResult<()> {
        if self.identity.version == 1 {
            return Ok(());
        }
        let head = self.removal_global_head(snapshot)?;
        let mut previous = genesis(&self.identity)?;
        let mut workspaces = BTreeMap::new();
        for sequence in 1..=head.sequence {
            let event = self.read_removal_event(snapshot, sequence)?;
            if event.previous != previous.digest {
                return Err(integrity("retention authority chain is discontinuous"));
            }
            match &event.operation {
                Operation::RecordWitness { witness } => {
                    self.verify_record_witness_rows(snapshot, &event, witness, expected)?;
                }
                Operation::AssertionWitness { witness } => {
                    self.verify_assertion_witness_rows(snapshot, &event, witness, expected)?;
                }
                Operation::AssertionValues { witness } => {
                    self.verify_assertion_value_rows(snapshot, &event, witness, expected)?;
                }
                Operation::RecordValidation { validation } => {
                    self.verify_record_validation_rows(snapshot, &event, validation, expected)?;
                }
                Operation::RawCopies { observation } => {
                    if !workspaces.contains_key(&observation.workspace) {
                        return Err(integrity(
                            "raw copy observation precedes workspace registration",
                        ));
                    }
                    self.verify_raw_copy_rows(snapshot, &event, observation, expected)?;
                }
                Operation::RawIndexInventory { witness } => {
                    self.verify_raw_index_inventory_rows(snapshot, &event, witness, expected)?;
                }
                Operation::OwnedKeys { witness } => {
                    self.verify_owned_key_rows(snapshot, &event, witness, expected)?;
                }
                Operation::PrimaryKeys { witness } => {
                    self.verify_primary_key_rows(snapshot, &event, witness, expected)?;
                }
                Operation::Register { workspace } => {
                    if workspaces
                        .insert(workspace.clone(), self.removal_genesis(workspace)?)
                        .is_some()
                    {
                        return Err(integrity("retention workspace was registered twice"));
                    }
                }
                Operation::Request {
                    intent,
                    source_pages,
                    payload_pages,
                } => {
                    if workspaces.get(&intent.workspace) != Some(&intent.previous)
                        || expected
                            .insert(
                                retry_key(&intent.workspace, &intent.retry_key),
                                encode(&event.checkpoint())?,
                            )
                            .is_some()
                    {
                        return Err(integrity("retention request forks or reuses a retry key"));
                    }
                    workspaces.insert(intent.workspace.clone(), event.checkpoint());
                    expected.insert(
                        request_key(&intent.workspace, sequence),
                        encode(&event.checkpoint())?,
                    );
                    let mut budget = inventory::verification_budget();
                    let inventory = self.read_removal_inventory(snapshot, intent, &mut budget)?;
                    if inventory::source_page_digests(&inventory)? != *source_pages
                        || inventory::payload_page_digests(&inventory)? != *payload_pages
                    {
                        return Err(integrity(
                            "retained source page manifest differs from inventory",
                        ));
                    }
                    for (key, value) in inventory::rows(&inventory, &mut budget)? {
                        expected.insert(key, value);
                    }
                    for source in &inventory.sources {
                        let value = encode(&source.receipt.event_digest)?;
                        if expected
                            .insert(
                                denied_key(&intent.workspace, source.receipt.event_id),
                                value.clone(),
                            )
                            .is_some_and(|previous| previous != value)
                        {
                            return Err(integrity(
                                "retention source identity changed across requests",
                            ));
                        }
                    }
                }
            }
            previous = event.checkpoint();
            expected.insert(event_key(sequence), encode(&event)?);
        }
        if previous != head {
            return Err(integrity("retention authority terminal differs"));
        }
        expected.insert(HEAD.to_vec(), encode(&head)?);
        for (workspace, checkpoint) in workspaces {
            expected.insert(current_key(&workspace), encode(&checkpoint)?);
        }
        Ok(())
    }
}

fn current_key(workspace: &str) -> Vec<u8> {
    format!("removal/current/{workspace}").into_bytes()
}
fn event_key(sequence: u64) -> Vec<u8> {
    format!("removal/event/{sequence:020}").into_bytes()
}
fn request_key(workspace: &str, sequence: u64) -> Vec<u8> {
    format!("removal/request/{workspace}/{sequence:020}").into_bytes()
}
fn retry_key(workspace: &str, retry: &str) -> Vec<u8> {
    format!("removal/retry/{workspace}/{retry}").into_bytes()
}
fn denied_key(workspace: &str, id: ObservationId) -> Vec<u8> {
    format!("removal/denied/{workspace}/{id}").into_bytes()
}
fn valid_digest(value: &str) -> ServiceResult<()> {
    if blake3::Hash::from_hex(value).is_err() {
        return Err(integrity("retention digest is invalid"));
    }
    Ok(())
}
