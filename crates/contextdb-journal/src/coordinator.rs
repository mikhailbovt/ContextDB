use std::fmt;
use std::sync::{Mutex, MutexGuard};

use contextdb_core::{CommitSeq, DerivedWorkItem, MutationId, ObservationId, PublicationId};
use contextdb_format::{RecordEnvelope, RecordKind};
use contextdb_storage::{
    Durability, Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine, VerifyMode,
    WriteTransaction,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::key::{
    EVENT_PREFIX, HEAD_KEY, IDEMPOTENCY_PREFIX, Keyspaces, MUTATION_PREFIX, OBSERVATION_PREFIX,
    OUTBOX_PREFIX, event_key, idempotency_key, mutation_key, observation_key, outbox_key,
    outbox_sequence_prefix, sequence_from_key,
};
use crate::{
    CommitOptions, CommitStage, IdempotencyKey, JournalError, JournalEvent, JournalSnapshot,
    JournalSnapshotSelector, JournalVerifyReport, MaintenanceReceipt, ObservationReceipt,
    PortableJournalBackup, PublicationReceipt, RecoveryReport, ReplayMaintenance, ReplayMutation,
    RestoreReport, Result, ValidatedMaintenanceBytes, ValidatedMutationBytes,
    ValidatedObservationBytes,
};

const SCHEMA_VERSION: u16 = 1;
const BACKUP_SCHEMA_VERSION: u16 = 1;

/// Serializes logical commits above an atomic physical storage engine.
///
/// Construction performs recovery: unpublished keyed tail records are removed,
/// then the complete prefix named by the checksummed head record is validated.
pub struct JournalCoordinator<E: StorageEngine> {
    engine: E,
    keyspaces: Keyspaces,
    commit_lock: Mutex<()>,
}

impl<E: StorageEngine> fmt::Debug for JournalCoordinator<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JournalCoordinator")
            .finish_non_exhaustive()
    }
}

impl<E: StorageEngine> JournalCoordinator<E> {
    /// Opens a coordinator and synchronously recovers its durable prefix.
    pub fn new(engine: E) -> Result<Self> {
        let coordinator = Self {
            engine,
            keyspaces: Keyspaces::new()?,
            commit_lock: Mutex::new(()),
        };
        coordinator.recover()?;
        Ok(coordinator)
    }

    /// Returns the underlying engine for backend-specific lifecycle operations.
    #[must_use]
    pub const fn engine(&self) -> &E {
        &self.engine
    }

    /// Consumes the coordinator and returns its physical engine.
    #[must_use]
    pub fn into_engine(self) -> E {
        self.engine
    }

    /// Atomically accepts one immutable observation as its own logical frame.
    pub fn accept_observation(
        &self,
        idempotency: &IdempotencyKey,
        observation: &ValidatedObservationBytes,
        options: CommitOptions,
    ) -> Result<ObservationReceipt> {
        let _guard = self.lock_commits()?;
        let key_digest = idempotency.digest();
        if let Some(receipt) =
            self.read_observation_retry(&key_digest, observation.digest(), options.durability)?
        {
            return Ok(receipt);
        }

        fail_if(options.fail_at, CommitStage::AfterValidation)?;
        let mut transaction = self.engine.begin_write()?;
        let head = self.logical_head(&transaction)?;
        let next = head
            .checked_next()
            .ok_or(JournalError::CommitSequenceExhausted)?;

        if transaction
            .get(
                &self.keyspaces.observations,
                &observation_key(observation.observation_id()),
            )?
            .is_some()
        {
            return Err(JournalError::DuplicateObservation);
        }

        let event_payload = ObservationFramePayload {
            observation_id: observation.observation_id(),
            request_digest: observation.digest(),
            exact_bytes: observation.exact_bytes().to_vec(),
        };
        transaction.put(
            &self.keyspaces.events,
            event_key(next.get()),
            encode(RecordKind::Observation, next, &event_payload)?,
        )?;
        transaction.put(
            &self.keyspaces.observations,
            observation_key(observation.observation_id()),
            encode(
                RecordKind::Snapshot,
                next,
                &IdentityIndexPayload {
                    commit_seq: next,
                    request_digest: observation.digest(),
                },
            )?,
        )?;

        let receipt = ObservationReceipt {
            observation_id: observation.observation_id(),
            commit_seq: next,
            durability: options.durability,
            replayed: false,
            request_digest: observation.digest(),
        };
        transaction.put(
            &self.keyspaces.idempotency,
            idempotency_key(&key_digest),
            encode(
                RecordKind::Snapshot,
                next,
                &IdempotencyPayload {
                    key_digest,
                    request_digest: observation.digest(),
                    receipt: StoredReceipt::Observation(receipt),
                },
            )?,
        )?;
        self.stage_head(&mut transaction, next)?;

        if options.fail_at == Some(CommitStage::AfterStaging) {
            transaction.rollback()?;
            return Err(JournalError::InjectedFailure(CommitStage::AfterStaging));
        }
        let physical = transaction.commit(options.durability)?;
        ensure_durability(next, options.durability, physical.durability)?;
        if options.fail_at == Some(CommitStage::AfterCommitBeforeAck) {
            return Err(JournalError::LostResponse { commit_seq: next });
        }
        Ok(receipt)
    }

    /// Atomically publishes exact mutation bytes, its publication frame, and
    /// every rebuildable derived-work descriptor.
    pub fn publish_semantic(
        &self,
        idempotency: &IdempotencyKey,
        mutation: &ValidatedMutationBytes,
        options: CommitOptions,
    ) -> Result<PublicationReceipt> {
        let _guard = self.lock_commits()?;
        let key_digest = idempotency.digest();
        if let Some(receipt) =
            self.read_publication_retry(&key_digest, mutation.digest(), options.durability)?
        {
            return Ok(receipt);
        }

        fail_if(options.fail_at, CommitStage::AfterValidation)?;
        let mut transaction = self.engine.begin_write()?;
        let head = self.logical_head(&transaction)?;
        if mutation.mutation().base_snapshot.commit_seq != head {
            return Err(JournalError::BaseSnapshotMismatch {
                base: mutation.mutation().base_snapshot.commit_seq,
                head,
            });
        }
        for observation_id in mutation.mutation().journal_refs.iter().copied() {
            self.validate_observation_reference(&transaction, observation_id, head)?;
        }
        if transaction
            .get(
                &self.keyspaces.mutations,
                &mutation_key(mutation.mutation_id()),
            )?
            .is_some()
        {
            return Err(JournalError::IdempotencyConflict);
        }

        let next = head
            .checked_next()
            .ok_or(JournalError::CommitSequenceExhausted)?;
        let publication_id = PublicationId::new();
        let outbox_count = u32::try_from(mutation.mutation().derived_work.len()).map_err(|_| {
            JournalError::Corruption {
                reason: "derived-work count exceeds portable u32 range".to_owned(),
            }
        })?;

        transaction.put(
            &self.keyspaces.mutations,
            mutation_key(mutation.mutation_id()),
            encode(
                RecordKind::SemanticMutation,
                next,
                &SemanticMutationFramePayload {
                    mutation_id: mutation.mutation_id(),
                    mutation_digest: mutation.digest(),
                    exact_bytes: mutation.exact_bytes().to_vec(),
                },
            )?,
        )?;
        transaction.put(
            &self.keyspaces.events,
            event_key(next.get()),
            encode(
                RecordKind::SemanticPublication,
                next,
                &SemanticPublicationFramePayload {
                    mutation_id: mutation.mutation_id(),
                    publication_id,
                    mutation_digest: mutation.digest(),
                    outbox_count,
                },
            )?,
        )?;
        for (index, work) in mutation.mutation().derived_work.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| JournalError::Corruption {
                reason: "derived-work index exceeds portable u32 range".to_owned(),
            })?;
            transaction.put(
                &self.keyspaces.outbox,
                outbox_key(next.get(), index),
                encode(
                    RecordKind::Outbox,
                    next,
                    &OutboxFramePayload {
                        mutation_id: mutation.mutation_id(),
                        index,
                        work: work.clone(),
                    },
                )?,
            )?;
        }

        let receipt = PublicationReceipt {
            mutation_id: mutation.mutation_id(),
            publication_id,
            commit_seq: next,
            durability: options.durability,
            outbox_count,
            replayed: false,
            mutation_digest: mutation.digest(),
        };
        transaction.put(
            &self.keyspaces.idempotency,
            idempotency_key(&key_digest),
            encode(
                RecordKind::Snapshot,
                next,
                &IdempotencyPayload {
                    key_digest,
                    request_digest: mutation.digest(),
                    receipt: StoredReceipt::Publication(receipt),
                },
            )?,
        )?;
        self.stage_head(&mut transaction, next)?;

        if options.fail_at == Some(CommitStage::AfterStaging) {
            transaction.rollback()?;
            return Err(JournalError::InjectedFailure(CommitStage::AfterStaging));
        }
        let physical = transaction.commit(options.durability)?;
        ensure_durability(next, options.durability, physical.durability)?;
        if options.fail_at == Some(CommitStage::AfterCommitBeforeAck) {
            return Err(JournalError::LostResponse { commit_seq: next });
        }
        Ok(receipt)
    }

    /// Atomically publishes an exact policy/maintenance mutation, its small
    /// generation-switch record, and all rebuildable outbox descriptors.
    pub fn publish_maintenance(
        &self,
        idempotency: &IdempotencyKey,
        mutation: &ValidatedMaintenanceBytes,
        options: CommitOptions,
    ) -> Result<MaintenanceReceipt> {
        let _guard = self.lock_commits()?;
        let key_digest = idempotency.digest();
        if let Some(receipt) =
            self.read_maintenance_retry(&key_digest, mutation.digest(), options.durability)?
        {
            return Ok(receipt);
        }

        fail_if(options.fail_at, CommitStage::AfterValidation)?;
        let mut transaction = self.engine.begin_write()?;
        let head = self.logical_head(&transaction)?;
        if mutation.mutation().base_snapshot.commit_seq != head {
            return Err(JournalError::BaseSnapshotMismatch {
                base: mutation.mutation().base_snapshot.commit_seq,
                head,
            });
        }
        if transaction
            .get(
                &self.keyspaces.mutations,
                &mutation_key(mutation.mutation_id()),
            )?
            .is_some()
        {
            return Err(JournalError::IdempotencyConflict);
        }

        let next = head
            .checked_next()
            .ok_or(JournalError::CommitSequenceExhausted)?;
        let publication_id = PublicationId::new();
        let outbox_count = u32::try_from(mutation.mutation().derived_work.len()).map_err(|_| {
            JournalError::Corruption {
                reason: "derived-work count exceeds portable u32 range".to_owned(),
            }
        })?;
        transaction.put(
            &self.keyspaces.mutations,
            mutation_key(mutation.mutation_id()),
            encode(
                RecordKind::MaintenanceMutation,
                next,
                &SemanticMutationFramePayload {
                    mutation_id: mutation.mutation_id(),
                    mutation_digest: mutation.digest(),
                    exact_bytes: mutation.exact_bytes().to_vec(),
                },
            )?,
        )?;
        transaction.put(
            &self.keyspaces.events,
            event_key(next.get()),
            encode(
                RecordKind::MaintenancePublication,
                next,
                &SemanticPublicationFramePayload {
                    mutation_id: mutation.mutation_id(),
                    publication_id,
                    mutation_digest: mutation.digest(),
                    outbox_count,
                },
            )?,
        )?;
        for (index, work) in mutation.mutation().derived_work.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| JournalError::Corruption {
                reason: "derived-work index exceeds portable u32 range".to_owned(),
            })?;
            transaction.put(
                &self.keyspaces.outbox,
                outbox_key(next.get(), index),
                encode(
                    RecordKind::Outbox,
                    next,
                    &OutboxFramePayload {
                        mutation_id: mutation.mutation_id(),
                        index,
                        work: work.clone(),
                    },
                )?,
            )?;
        }

        let receipt = MaintenanceReceipt {
            mutation_id: mutation.mutation_id(),
            publication_id,
            commit_seq: next,
            durability: options.durability,
            outbox_count,
            replayed: false,
            mutation_digest: mutation.digest(),
        };
        transaction.put(
            &self.keyspaces.idempotency,
            idempotency_key(&key_digest),
            encode(
                RecordKind::Snapshot,
                next,
                &IdempotencyPayload {
                    key_digest,
                    request_digest: mutation.digest(),
                    receipt: StoredReceipt::Maintenance(receipt),
                },
            )?,
        )?;
        self.stage_head(&mut transaction, next)?;

        if options.fail_at == Some(CommitStage::AfterStaging) {
            transaction.rollback()?;
            return Err(JournalError::InjectedFailure(CommitStage::AfterStaging));
        }
        let physical = transaction.commit(options.durability)?;
        ensure_durability(next, options.durability, physical.durability)?;
        if options.fail_at == Some(CommitStage::AfterCommitBeforeAck) {
            return Err(JournalError::LostResponse { commit_seq: next });
        }
        Ok(receipt)
    }

    /// Materializes a checksum-validated logical journal prefix.
    pub fn snapshot(&self, selector: JournalSnapshotSelector) -> Result<JournalSnapshot> {
        let snapshot = self.engine.begin_read(SnapshotSelector::Latest)?;
        let head = self.logical_head(&snapshot)?;
        let requested = match selector {
            JournalSnapshotSelector::Latest => head,
            JournalSnapshotSelector::At(sequence) => {
                if sequence.get() > head.get() {
                    return Err(JournalError::SnapshotUnavailable {
                        requested: sequence,
                        head,
                    });
                }
                sequence
            }
        };
        let entries = snapshot.scan_prefix(&self.keyspaces.events, EVENT_PREFIX)?;
        let requested_len =
            usize::try_from(requested.get()).map_err(|_| JournalError::Corruption {
                reason: "logical sequence cannot be represented on this platform".to_owned(),
            })?;
        let mut events = Vec::with_capacity(requested_len.min(entries.len()));
        let mut expected = 1_u64;
        for entry in entries {
            let sequence = sequence_from_key(&entry.key, EVENT_PREFIX, 0).ok_or_else(|| {
                JournalError::Corruption {
                    reason: "journal event has a malformed ordered key".to_owned(),
                }
            })?;
            if sequence > requested.get() {
                continue;
            }
            if sequence != expected {
                return Err(JournalError::Corruption {
                    reason: format!(
                        "logical journal is not contiguous: expected {expected}, found {sequence}"
                    ),
                });
            }
            events.push(self.materialize_event(&snapshot, sequence, &entry.value)?);
            expected = expected.saturating_add(1);
        }
        if events.len() != requested_len {
            return Err(JournalError::Corruption {
                reason: format!(
                    "logical head {} names {} events but {} were materialized",
                    requested.get(),
                    requested.get(),
                    events.len()
                ),
            });
        }
        Ok(JournalSnapshot {
            commit_seq: requested,
            storage_sequence: snapshot.sequence(),
            events,
        })
    }

    /// Returns exact validated semantic mutation bytes in publication order.
    pub fn replay_mutations(
        &self,
        selector: JournalSnapshotSelector,
    ) -> Result<Vec<ReplayMutation>> {
        let snapshot = self.snapshot(selector)?;
        Ok(snapshot
            .events
            .into_iter()
            .filter_map(|event| match event {
                JournalEvent::SemanticPublished {
                    commit_seq,
                    mutation_id,
                    mutation_digest,
                    exact_mutation_bytes,
                    ..
                } => Some(ReplayMutation {
                    commit_seq,
                    mutation_id,
                    mutation_digest,
                    exact_bytes: exact_mutation_bytes,
                }),
                JournalEvent::ObservationAccepted { .. }
                | JournalEvent::MaintenancePublished { .. } => None,
            })
            .collect())
    }

    /// Returns exact validated policy/maintenance bytes in publication order.
    pub fn replay_maintenance(
        &self,
        selector: JournalSnapshotSelector,
    ) -> Result<Vec<ReplayMaintenance>> {
        let snapshot = self.snapshot(selector)?;
        Ok(snapshot
            .events
            .into_iter()
            .filter_map(|event| match event {
                JournalEvent::MaintenancePublished {
                    commit_seq,
                    mutation_id,
                    mutation_digest,
                    exact_mutation_bytes,
                    ..
                } => Some(ReplayMaintenance {
                    commit_seq,
                    mutation_id,
                    mutation_digest,
                    exact_bytes: exact_mutation_bytes,
                }),
                JournalEvent::ObservationAccepted { .. }
                | JournalEvent::SemanticPublished { .. } => None,
            })
            .collect())
    }

    /// Creates a self-verifying, backend-independent backup of the complete
    /// logical journal at the latest published head.
    ///
    /// The commit mutex prevents a writer from advancing between verification
    /// and snapshot capture. Every key and value remains in ContextDB's own
    /// portable record format; no Fjall/redb physical pages are copied.
    pub fn create_backup(&self) -> Result<PortableJournalBackup> {
        let _guard = self.lock_commits()?;
        let verified = self.verify(VerifyMode::Deep)?;
        let snapshot = self.engine.begin_read(SnapshotSelector::Latest)?;
        let mut sections = Vec::new();
        let mut records = 0_u64;
        for (name, keyspace) in self.portable_keyspaces() {
            let entries = snapshot
                .scan_prefix(keyspace, b"")?
                .into_iter()
                .map(|entry| BackupEntry {
                    key: entry.key,
                    value: entry.value,
                })
                .collect::<Vec<_>>();
            records = records
                .checked_add(u64::try_from(entries.len()).map_err(|_| {
                    JournalError::InvalidBackup {
                        reason: "record count exceeds portable u64 range".to_owned(),
                    }
                })?)
                .ok_or_else(|| JournalError::InvalidBackup {
                    reason: "record count overflow".to_owned(),
                })?;
            sections.push(BackupSection {
                name: name.to_owned(),
                entries,
            });
        }
        let payload = serde_json::to_vec(&BackupPayload {
            schema_version: BACKUP_SCHEMA_VERSION,
            commit_seq: verified.commit_seq,
            records,
            sections,
        })?;
        let payload_digest = *blake3::hash(&payload).as_bytes();
        Ok(PortableJournalBackup {
            schema_version: BACKUP_SCHEMA_VERSION,
            commit_seq: verified.commit_seq,
            records,
            payload_digest,
            payload,
        })
    }

    /// Atomically restores a portable logical backup into an empty engine.
    ///
    /// A non-empty target is rejected instead of merged. The raw portable
    /// frames are installed in one synchronized storage transaction and then
    /// subjected to normal recovery and deep verification before success.
    pub fn restore_backup(
        engine: E,
        backup: &PortableJournalBackup,
    ) -> Result<(Self, RestoreReport)> {
        let coordinator = Self::new(engine)?;
        let actual_digest = *blake3::hash(&backup.payload).as_bytes();
        if backup.schema_version != BACKUP_SCHEMA_VERSION || backup.payload_digest != actual_digest
        {
            return Err(JournalError::InvalidBackup {
                reason: "container schema or payload digest mismatch".to_owned(),
            });
        }
        let payload: BackupPayload = serde_json::from_slice(&backup.payload)?;
        coordinator.validate_backup_payload(&payload, backup)?;

        let guard = coordinator.lock_commits()?;
        let target = coordinator.engine.begin_read(SnapshotSelector::Latest)?;
        for (_, keyspace) in coordinator.portable_keyspaces() {
            if !target.scan_prefix(keyspace, b"")?.is_empty() {
                return Err(JournalError::RestoreTargetNotEmpty);
            }
        }
        drop(target);

        let mut transaction = coordinator.engine.begin_write()?;
        for section in &payload.sections {
            let keyspace = coordinator
                .portable_keyspace(&section.name)
                .ok_or_else(|| JournalError::InvalidBackup {
                    reason: "backup contains an unknown keyspace".to_owned(),
                })?;
            for entry in &section.entries {
                transaction.put(keyspace, entry.key.clone(), entry.value.clone())?;
            }
        }
        let receipt = transaction.commit(Durability::Sync)?;
        ensure_durability(payload.commit_seq, Durability::Sync, receipt.durability)?;
        drop(guard);

        let recovery = coordinator.recover()?;
        if recovery.removed_tail_records != 0 {
            return Err(JournalError::InvalidBackup {
                reason: "restore input required unpublished-tail recovery".to_owned(),
            });
        }
        let verified = coordinator.verify(VerifyMode::Deep)?;
        if recovery.commit_seq != payload.commit_seq || verified.commit_seq != payload.commit_seq {
            return Err(JournalError::InvalidBackup {
                reason: "restored logical head differs from backup manifest".to_owned(),
            });
        }
        let installed = coordinator.create_backup()?;
        if installed != *backup {
            return Err(JournalError::InvalidBackup {
                reason: "installed journal differs from the exact backup manifest".to_owned(),
            });
        }
        Ok((
            coordinator,
            RestoreReport {
                commit_seq: installed.commit_seq,
                records: installed.records,
                payload_digest: installed.payload_digest,
                storage_sequence: receipt.sequence,
            },
        ))
    }

    /// Removes keyed records beyond the authoritative logical head and validates
    /// that the retained prefix is complete. Prefix corruption is never repaired.
    pub fn recover(&self) -> Result<RecoveryReport> {
        let _guard = self.lock_commits()?;
        let snapshot = self.engine.begin_read(SnapshotSelector::Latest)?;
        let head = self.logical_head(&snapshot)?;
        let mut deletions = Vec::new();
        self.collect_keyed_tail(
            &snapshot,
            &self.keyspaces.events,
            EVENT_PREFIX,
            0,
            head,
            &mut deletions,
        )?;
        self.collect_keyed_tail(
            &snapshot,
            &self.keyspaces.outbox,
            OUTBOX_PREFIX,
            4,
            head,
            &mut deletions,
        )?;
        self.collect_framed_tail(
            &snapshot,
            &self.keyspaces.mutations,
            MUTATION_PREFIX,
            head,
            &mut deletions,
        )?;
        self.collect_framed_tail(
            &snapshot,
            &self.keyspaces.observations,
            OBSERVATION_PREFIX,
            head,
            &mut deletions,
        )?;
        self.collect_framed_tail(
            &snapshot,
            &self.keyspaces.idempotency,
            IDEMPOTENCY_PREFIX,
            head,
            &mut deletions,
        )?;
        drop(snapshot);

        let removed_tail_records = u64::try_from(deletions.len()).unwrap_or(u64::MAX);
        let mut warnings = Vec::new();
        if !deletions.is_empty() {
            let mut transaction = self.engine.begin_write()?;
            for (keyspace, key) in deletions {
                transaction.delete(&keyspace, key)?;
            }
            let receipt = transaction.commit(Durability::Sync)?;
            if receipt.durability != Durability::Sync {
                return Err(JournalError::DurabilityNotAchieved {
                    commit_seq: head,
                    requested: Durability::Sync,
                    achieved: receipt.durability,
                });
            }
            warnings.push(format!(
                "removed {removed_tail_records} unpublished tail records"
            ));
        }

        // The complete prefix is materialized after cleanup so checksum, exact
        // bytes, mutation references, and atomic outbox cardinality all agree.
        let validated = self.snapshot(JournalSnapshotSelector::Latest)?;
        Ok(RecoveryReport {
            commit_seq: validated.commit_seq,
            storage_sequence: validated.storage_sequence,
            removed_tail_records,
            warnings,
        })
    }

    /// Verifies the physical engine and all journal-level framing invariants.
    pub fn verify(&self, mode: VerifyMode) -> Result<JournalVerifyReport> {
        let physical = self.engine.verify(mode)?;
        let logical = self.snapshot(JournalSnapshotSelector::Latest)?;
        let snapshot = self.engine.begin_read(SnapshotSelector::Latest)?;
        let idempotency = snapshot.scan_prefix(&self.keyspaces.idempotency, IDEMPOTENCY_PREFIX)?;
        for entry in &idempotency {
            let record = decode_any::<IdempotencyPayload>(&entry.value, RecordKind::Snapshot)?;
            if record.sequence.get() > logical.commit_seq.get() {
                return Err(JournalError::Corruption {
                    reason: "idempotency record exists beyond logical head".to_owned(),
                });
            }
            if idempotency_key(&record.value.key_digest) != entry.key {
                return Err(JournalError::Corruption {
                    reason: "idempotency record key digest mismatch".to_owned(),
                });
            }
        }
        let outbox = snapshot.scan_prefix(&self.keyspaces.outbox, OUTBOX_PREFIX)?;
        for entry in &outbox {
            let sequence = sequence_from_key(&entry.key, OUTBOX_PREFIX, 4).ok_or_else(|| {
                JournalError::Corruption {
                    reason: "outbox record has malformed ordered key".to_owned(),
                }
            })?;
            let _: OutboxFramePayload =
                decode(&entry.value, RecordKind::Outbox, CommitSeq::new(sequence))?;
        }

        let expected_outbox = logical.events.iter().try_fold(0_u64, |count, event| {
            let increment = match event {
                JournalEvent::SemanticPublished { outbox, .. }
                | JournalEvent::MaintenancePublished { outbox, .. } => u64::try_from(outbox.len())
                    .map_err(|_| JournalError::Corruption {
                        reason: "outbox length exceeds u64".to_owned(),
                    })?,
                JournalEvent::ObservationAccepted { .. } => 0,
            };
            count
                .checked_add(increment)
                .ok_or_else(|| JournalError::Corruption {
                    reason: "outbox count overflow".to_owned(),
                })
        })?;
        if expected_outbox != u64::try_from(outbox.len()).unwrap_or(u64::MAX) {
            return Err(JournalError::Corruption {
                reason: "materialized outbox count does not match durable frames".to_owned(),
            });
        }
        if logical.events.len() != idempotency.len() {
            return Err(JournalError::Corruption {
                reason: "logical event and idempotency receipt counts differ".to_owned(),
            });
        }

        Ok(JournalVerifyReport {
            mode,
            commit_seq: logical.commit_seq,
            storage_sequence: physical.sequence,
            events: u64::try_from(logical.events.len()).unwrap_or(u64::MAX),
            outbox_records: u64::try_from(outbox.len()).unwrap_or(u64::MAX),
            idempotency_records: u64::try_from(idempotency.len()).unwrap_or(u64::MAX),
            warnings: physical.warnings,
        })
    }

    fn lock_commits(&self) -> Result<MutexGuard<'_, ()>> {
        self.commit_lock
            .lock()
            .map_err(|_| JournalError::CoordinatorPoisoned)
    }

    fn portable_keyspaces(&self) -> [(&'static str, &Keyspace); 6] {
        [
            ("journal_meta", &self.keyspaces.meta),
            ("semantic_journal", &self.keyspaces.events),
            ("journal_outbox", &self.keyspaces.outbox),
            ("journal_idempotency", &self.keyspaces.idempotency),
            ("journal_observation", &self.keyspaces.observations),
            ("journal_mutation", &self.keyspaces.mutations),
        ]
    }

    fn portable_keyspace(&self, name: &str) -> Option<&Keyspace> {
        self.portable_keyspaces()
            .into_iter()
            .find_map(|(candidate, keyspace)| (candidate == name).then_some(keyspace))
    }

    fn validate_backup_payload(
        &self,
        payload: &BackupPayload,
        container: &PortableJournalBackup,
    ) -> Result<()> {
        if payload.schema_version != BACKUP_SCHEMA_VERSION
            || payload.commit_seq != container.commit_seq
            || payload.records != container.records
        {
            return Err(JournalError::InvalidBackup {
                reason: "payload metadata differs from container manifest".to_owned(),
            });
        }
        let expected_names = self.portable_keyspaces().map(|(name, _)| name.to_owned());
        let actual_names = payload
            .sections
            .iter()
            .map(|section| section.name.clone())
            .collect::<Vec<_>>();
        if actual_names != expected_names {
            return Err(JournalError::InvalidBackup {
                reason: "portable keyspace manifest is missing, duplicated, or reordered"
                    .to_owned(),
            });
        }
        let mut records = 0_u64;
        for section in &payload.sections {
            if section
                .entries
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
                || section.entries.iter().any(|entry| entry.key.is_empty())
            {
                return Err(JournalError::InvalidBackup {
                    reason: "backup keys are empty, duplicated, or not bytewise ordered".to_owned(),
                });
            }
            records = records
                .checked_add(u64::try_from(section.entries.len()).map_err(|_| {
                    JournalError::InvalidBackup {
                        reason: "record count exceeds portable u64 range".to_owned(),
                    }
                })?)
                .ok_or_else(|| JournalError::InvalidBackup {
                    reason: "record count overflow".to_owned(),
                })?;
            for entry in &section.entries {
                let sequence = match section.name.as_str() {
                    "semantic_journal" => sequence_from_key(&entry.key, EVENT_PREFIX, 0),
                    "journal_outbox" => sequence_from_key(&entry.key, OUTBOX_PREFIX, 4),
                    "journal_mutation" | "journal_observation" | "journal_idempotency" => Some(
                        RecordEnvelope::decode(&entry.value)
                            .map_err(|_| JournalError::InvalidBackup {
                                reason: format!(
                                    "backup {} entry is not a valid framed record",
                                    section.name
                                ),
                            })?
                            .envelope
                            .commit_seq,
                    ),
                    "journal_meta" => None,
                    _ => unreachable!("keyspace names were checked above"),
                };
                if matches!(section.name.as_str(), "semantic_journal" | "journal_outbox")
                    && sequence.is_none()
                {
                    return Err(JournalError::InvalidBackup {
                        reason: format!(
                            "backup {} entry key has invalid ordered shape",
                            section.name
                        ),
                    });
                }
                if sequence.is_some_and(|value| value > payload.commit_seq.get()) {
                    return Err(JournalError::InvalidBackup {
                        reason: format!(
                            "backup {} contains an unpublished tail record",
                            section.name
                        ),
                    });
                }
            }
        }
        if records != payload.records {
            return Err(JournalError::InvalidBackup {
                reason: "payload record count mismatch".to_owned(),
            });
        }
        Ok(())
    }

    fn logical_head<R: ReadSnapshot>(&self, snapshot: &R) -> Result<CommitSeq> {
        let Some(bytes) = snapshot.get(&self.keyspaces.meta, HEAD_KEY)? else {
            return Ok(CommitSeq::GENESIS);
        };
        let record = decode_any::<HeadPayload>(&bytes, RecordKind::Snapshot)?;
        if record.value.commit_seq != record.sequence {
            return Err(JournalError::Corruption {
                reason: "head payload and envelope sequence differ".to_owned(),
            });
        }
        Ok(record.sequence)
    }

    fn stage_head<T: WriteTransaction>(&self, transaction: &mut T, head: CommitSeq) -> Result<()> {
        transaction.put(
            &self.keyspaces.meta,
            HEAD_KEY.to_vec(),
            encode(
                RecordKind::Snapshot,
                head,
                &HeadPayload { commit_seq: head },
            )?,
        )?;
        Ok(())
    }

    fn read_observation_retry(
        &self,
        key_digest: &[u8; 32],
        request_digest: [u8; 32],
        requested: Durability,
    ) -> Result<Option<ObservationReceipt>> {
        let Some(stored) = self.read_idempotency(key_digest)? else {
            return Ok(None);
        };
        if stored.key_digest != *key_digest || stored.request_digest != request_digest {
            return Err(JournalError::IdempotencyConflict);
        }
        let StoredReceipt::Observation(mut receipt) = stored.receipt else {
            return Err(JournalError::IdempotencyConflict);
        };
        ensure_durability(receipt.commit_seq, requested, receipt.durability)?;
        self.synchronize_retry_if_required(receipt.commit_seq, requested)?;
        receipt.replayed = true;
        Ok(Some(receipt))
    }

    fn read_publication_retry(
        &self,
        key_digest: &[u8; 32],
        request_digest: [u8; 32],
        requested: Durability,
    ) -> Result<Option<PublicationReceipt>> {
        let Some(stored) = self.read_idempotency(key_digest)? else {
            return Ok(None);
        };
        if stored.key_digest != *key_digest || stored.request_digest != request_digest {
            return Err(JournalError::IdempotencyConflict);
        }
        let StoredReceipt::Publication(mut receipt) = stored.receipt else {
            return Err(JournalError::IdempotencyConflict);
        };
        ensure_durability(receipt.commit_seq, requested, receipt.durability)?;
        self.synchronize_retry_if_required(receipt.commit_seq, requested)?;
        receipt.replayed = true;
        Ok(Some(receipt))
    }

    fn read_maintenance_retry(
        &self,
        key_digest: &[u8; 32],
        request_digest: [u8; 32],
        requested: Durability,
    ) -> Result<Option<MaintenanceReceipt>> {
        let Some(stored) = self.read_idempotency(key_digest)? else {
            return Ok(None);
        };
        if stored.key_digest != *key_digest || stored.request_digest != request_digest {
            return Err(JournalError::IdempotencyConflict);
        }
        let StoredReceipt::Maintenance(mut receipt) = stored.receipt else {
            return Err(JournalError::IdempotencyConflict);
        };
        ensure_durability(receipt.commit_seq, requested, receipt.durability)?;
        self.synchronize_retry_if_required(receipt.commit_seq, requested)?;
        receipt.replayed = true;
        Ok(Some(receipt))
    }

    fn read_idempotency(&self, key_digest: &[u8; 32]) -> Result<Option<IdempotencyPayload>> {
        let snapshot = self.engine.begin_read(SnapshotSelector::Latest)?;
        let Some(bytes) =
            snapshot.get(&self.keyspaces.idempotency, &idempotency_key(key_digest))?
        else {
            return Ok(None);
        };
        Ok(Some(
            decode_any::<IdempotencyPayload>(&bytes, RecordKind::Snapshot)?.value,
        ))
    }

    fn synchronize_retry_if_required(
        &self,
        commit_seq: CommitSeq,
        requested: Durability,
    ) -> Result<()> {
        if requested == Durability::Sync {
            // A retry cannot know whether the original response was lost before
            // the caller observed the backend's achieved durability. A Sync
            // barrier makes the complete earlier atomic transaction durable
            // before reconstructing its acknowledgement.
            let transaction = self.engine.begin_write()?;
            let receipt = transaction.commit(Durability::Sync)?;
            ensure_durability(commit_seq, Durability::Sync, receipt.durability)?;
        }
        Ok(())
    }

    fn validate_observation_reference<R: ReadSnapshot>(
        &self,
        snapshot: &R,
        observation_id: ObservationId,
        head: CommitSeq,
    ) -> Result<()> {
        self.observation_index(snapshot, observation_id, head)
            .map(|_| ())
    }

    fn observation_index<R: ReadSnapshot>(
        &self,
        snapshot: &R,
        observation_id: ObservationId,
        head: CommitSeq,
    ) -> Result<DecodedPayload<IdentityIndexPayload>> {
        let Some(bytes) = snapshot.get(
            &self.keyspaces.observations,
            &observation_key(observation_id),
        )?
        else {
            return Err(JournalError::MissingObservation(observation_id));
        };
        let record = decode_any::<IdentityIndexPayload>(&bytes, RecordKind::Snapshot)?;
        if record.sequence != record.value.commit_seq || record.sequence.get() > head.get() {
            return Err(JournalError::Corruption {
                reason: "observation index points outside the published prefix".to_owned(),
            });
        }
        Ok(record)
    }

    fn materialize_event<R: ReadSnapshot>(
        &self,
        snapshot: &R,
        sequence: u64,
        bytes: &[u8],
    ) -> Result<JournalEvent> {
        let commit_seq = CommitSeq::new(sequence);
        let record = RecordEnvelope::decode(bytes)?;
        if record.envelope.schema_version != SCHEMA_VERSION
            || record.envelope.flags != 0
            || record.envelope.commit_seq != sequence
        {
            return Err(JournalError::Corruption {
                reason: format!("event envelope metadata is invalid at sequence {sequence}"),
            });
        }
        match record.envelope.record_kind {
            kind if kind == u16::from(RecordKind::Observation) => {
                let payload: ObservationFramePayload = serde_json::from_slice(record.payload)?;
                let validated = ValidatedObservationBytes::from_json(payload.exact_bytes.clone())?;
                if validated.observation_id() != payload.observation_id
                    || validated.digest() != payload.request_digest
                {
                    return Err(JournalError::Corruption {
                        reason: format!(
                            "observation exact bytes or digest mismatch at sequence {sequence}"
                        ),
                    });
                }
                let index = self.observation_index(snapshot, payload.observation_id, commit_seq)?;
                if index.sequence != commit_seq
                    || index.value.request_digest != payload.request_digest
                {
                    return Err(JournalError::Corruption {
                        reason: format!("observation index mismatch at sequence {sequence}"),
                    });
                }
                Ok(JournalEvent::ObservationAccepted {
                    commit_seq,
                    observation_id: payload.observation_id,
                    exact_bytes: payload.exact_bytes,
                    request_digest: payload.request_digest,
                })
            }
            kind if kind == u16::from(RecordKind::SemanticPublication) => {
                let publication: SemanticPublicationFramePayload =
                    serde_json::from_slice(record.payload)?;
                let mutation_bytes = snapshot
                    .get(
                        &self.keyspaces.mutations,
                        &mutation_key(publication.mutation_id),
                    )?
                    .ok_or_else(|| JournalError::Corruption {
                        reason: format!(
                            "publication at sequence {sequence} has no exact mutation frame"
                        ),
                    })?;
                let mutation: SemanticMutationFramePayload =
                    decode(&mutation_bytes, RecordKind::SemanticMutation, commit_seq)?;
                let validated = ValidatedMutationBytes::from_json(mutation.exact_bytes.clone())?;
                if mutation.mutation_id != publication.mutation_id
                    || mutation.mutation_digest != publication.mutation_digest
                    || validated.mutation_id() != publication.mutation_id
                    || validated.digest() != publication.mutation_digest
                {
                    return Err(JournalError::Corruption {
                        reason: format!(
                            "publication mutation bytes or digest mismatch at sequence {sequence}"
                        ),
                    });
                }
                let expected_base =
                    sequence
                        .checked_sub(1)
                        .ok_or_else(|| JournalError::Corruption {
                            reason: "semantic publication cannot occur at genesis".to_owned(),
                        })?;
                if validated.mutation().base_snapshot.commit_seq.get() != expected_base {
                    return Err(JournalError::Corruption {
                        reason: format!(
                            "semantic publication base mismatch at sequence {sequence}"
                        ),
                    });
                }
                for observation_id in validated.mutation().journal_refs.iter().copied() {
                    self.validate_observation_reference(
                        snapshot,
                        observation_id,
                        CommitSeq::new(expected_base),
                    )?;
                }
                let outbox_entries = snapshot
                    .scan_prefix(&self.keyspaces.outbox, &outbox_sequence_prefix(sequence))?;
                if outbox_entries.len()
                    != usize::try_from(publication.outbox_count).unwrap_or(usize::MAX)
                {
                    return Err(JournalError::Corruption {
                        reason: format!("publication outbox is incomplete at sequence {sequence}"),
                    });
                }
                let mut outbox = Vec::with_capacity(outbox_entries.len());
                for (expected_index, entry) in outbox_entries.into_iter().enumerate() {
                    let payload: OutboxFramePayload =
                        decode(&entry.value, RecordKind::Outbox, commit_seq)?;
                    if payload.mutation_id != publication.mutation_id
                        || usize::try_from(payload.index).ok() != Some(expected_index)
                        || entry.key != outbox_key(sequence, payload.index)
                    {
                        return Err(JournalError::Corruption {
                            reason: format!(
                                "publication outbox ordering mismatch at sequence {sequence}"
                            ),
                        });
                    }
                    outbox.push(payload.work);
                }
                if outbox != validated.mutation().derived_work {
                    return Err(JournalError::Corruption {
                        reason: format!(
                            "publication outbox content mismatch at sequence {sequence}"
                        ),
                    });
                }
                Ok(JournalEvent::SemanticPublished {
                    commit_seq,
                    mutation_id: publication.mutation_id,
                    publication_id: publication.publication_id,
                    exact_mutation_bytes: mutation.exact_bytes,
                    mutation_digest: publication.mutation_digest,
                    outbox,
                })
            }
            kind if kind == u16::from(RecordKind::MaintenancePublication) => {
                let publication: SemanticPublicationFramePayload =
                    serde_json::from_slice(record.payload)?;
                let mutation_bytes = snapshot
                    .get(
                        &self.keyspaces.mutations,
                        &mutation_key(publication.mutation_id),
                    )?
                    .ok_or_else(|| JournalError::Corruption {
                        reason: format!(
                            "maintenance publication at sequence {sequence} has no exact frame"
                        ),
                    })?;
                let mutation: SemanticMutationFramePayload =
                    decode(&mutation_bytes, RecordKind::MaintenanceMutation, commit_seq)?;
                let validated = ValidatedMaintenanceBytes::from_json(mutation.exact_bytes.clone())?;
                if mutation.mutation_id != publication.mutation_id
                    || mutation.mutation_digest != publication.mutation_digest
                    || validated.mutation_id() != publication.mutation_id
                    || validated.digest() != publication.mutation_digest
                {
                    return Err(JournalError::Corruption {
                        reason: format!(
                            "maintenance mutation bytes or digest mismatch at sequence {sequence}"
                        ),
                    });
                }
                let expected_base =
                    sequence
                        .checked_sub(1)
                        .ok_or_else(|| JournalError::Corruption {
                            reason: "maintenance publication cannot occur at genesis".to_owned(),
                        })?;
                if validated.mutation().base_snapshot.commit_seq.get() != expected_base {
                    return Err(JournalError::Corruption {
                        reason: format!(
                            "maintenance publication base mismatch at sequence {sequence}"
                        ),
                    });
                }
                let outbox_entries = snapshot
                    .scan_prefix(&self.keyspaces.outbox, &outbox_sequence_prefix(sequence))?;
                if outbox_entries.len()
                    != usize::try_from(publication.outbox_count).unwrap_or(usize::MAX)
                {
                    return Err(JournalError::Corruption {
                        reason: format!(
                            "maintenance publication outbox is incomplete at sequence {sequence}"
                        ),
                    });
                }
                let mut outbox = Vec::with_capacity(outbox_entries.len());
                for (expected_index, entry) in outbox_entries.into_iter().enumerate() {
                    let payload: OutboxFramePayload =
                        decode(&entry.value, RecordKind::Outbox, commit_seq)?;
                    if payload.mutation_id != publication.mutation_id
                        || usize::try_from(payload.index).ok() != Some(expected_index)
                        || entry.key != outbox_key(sequence, payload.index)
                    {
                        return Err(JournalError::Corruption {
                            reason: format!(
                                "maintenance outbox ordering mismatch at sequence {sequence}"
                            ),
                        });
                    }
                    outbox.push(payload.work);
                }
                if outbox != validated.mutation().derived_work {
                    return Err(JournalError::Corruption {
                        reason: format!(
                            "maintenance outbox content mismatch at sequence {sequence}"
                        ),
                    });
                }
                Ok(JournalEvent::MaintenancePublished {
                    commit_seq,
                    mutation_id: publication.mutation_id,
                    publication_id: publication.publication_id,
                    exact_mutation_bytes: mutation.exact_bytes,
                    mutation_digest: publication.mutation_digest,
                    outbox,
                })
            }
            other => Err(JournalError::Corruption {
                reason: format!("unsupported logical event kind {other} at sequence {sequence}"),
            }),
        }
    }

    fn collect_keyed_tail<R: ReadSnapshot>(
        &self,
        snapshot: &R,
        keyspace: &Keyspace,
        prefix: &[u8],
        suffix_len: usize,
        head: CommitSeq,
        deletions: &mut Vec<(Keyspace, Vec<u8>)>,
    ) -> Result<()> {
        for entry in snapshot.scan_prefix(keyspace, prefix)? {
            let sequence = sequence_from_key(&entry.key, prefix, suffix_len).ok_or_else(|| {
                JournalError::Corruption {
                    reason: "ordered journal key has invalid shape".to_owned(),
                }
            })?;
            if sequence > head.get() {
                deletions.push((keyspace.clone(), entry.key));
            }
        }
        Ok(())
    }

    fn collect_framed_tail<R: ReadSnapshot>(
        &self,
        snapshot: &R,
        keyspace: &Keyspace,
        prefix: &[u8],
        head: CommitSeq,
        deletions: &mut Vec<(Keyspace, Vec<u8>)>,
    ) -> Result<()> {
        for entry in snapshot.scan_prefix(keyspace, prefix)? {
            let record = RecordEnvelope::decode(&entry.value)?;
            if record.envelope.commit_seq > head.get() {
                deletions.push((keyspace.clone(), entry.key));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupPayload {
    schema_version: u16,
    commit_seq: CommitSeq,
    records: u64,
    sections: Vec<BackupSection>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupSection {
    name: String,
    entries: Vec<BackupEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupEntry {
    key: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadPayload {
    commit_seq: CommitSeq,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityIndexPayload {
    commit_seq: CommitSeq,
    request_digest: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationFramePayload {
    observation_id: ObservationId,
    request_digest: [u8; 32],
    exact_bytes: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticMutationFramePayload {
    mutation_id: MutationId,
    mutation_digest: [u8; 32],
    exact_bytes: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticPublicationFramePayload {
    mutation_id: MutationId,
    publication_id: PublicationId,
    mutation_digest: [u8; 32],
    outbox_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutboxFramePayload {
    mutation_id: MutationId,
    index: u32,
    work: DerivedWorkItem,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdempotencyPayload {
    key_digest: [u8; 32],
    request_digest: [u8; 32],
    receipt: StoredReceipt,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", content = "receipt", rename_all = "snake_case")]
enum StoredReceipt {
    Observation(ObservationReceipt),
    Publication(PublicationReceipt),
    Maintenance(MaintenanceReceipt),
}

struct DecodedPayload<T> {
    sequence: CommitSeq,
    value: T,
}

fn encode<T: Serialize>(kind: RecordKind, sequence: CommitSeq, value: &T) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(value)?;
    Ok(RecordEnvelope::encode(
        kind,
        SCHEMA_VERSION,
        0,
        sequence.get(),
        &payload,
    )?)
}

fn decode<T: DeserializeOwned>(bytes: &[u8], kind: RecordKind, sequence: CommitSeq) -> Result<T> {
    let decoded = decode_any::<T>(bytes, kind)?;
    if decoded.sequence != sequence {
        return Err(JournalError::Corruption {
            reason: format!(
                "frame sequence {} differs from expected {}",
                decoded.sequence, sequence
            ),
        });
    }
    Ok(decoded.value)
}

fn decode_any<T: DeserializeOwned>(bytes: &[u8], kind: RecordKind) -> Result<DecodedPayload<T>> {
    let record = RecordEnvelope::decode(bytes)?;
    if record.envelope.record_kind != u16::from(kind)
        || record.envelope.schema_version != SCHEMA_VERSION
        || record.envelope.flags != 0
    {
        return Err(JournalError::Corruption {
            reason: "record envelope kind, schema, or flags are invalid".to_owned(),
        });
    }
    Ok(DecodedPayload {
        sequence: CommitSeq::new(record.envelope.commit_seq),
        value: serde_json::from_slice(record.payload)?,
    })
}

fn fail_if(selected: Option<CommitStage>, stage: CommitStage) -> Result<()> {
    if selected == Some(stage) {
        return Err(JournalError::InjectedFailure(stage));
    }
    Ok(())
}

fn ensure_durability(
    commit_seq: CommitSeq,
    requested: Durability,
    achieved: Durability,
) -> Result<()> {
    if requested == Durability::Sync && achieved != Durability::Sync {
        return Err(JournalError::DurabilityNotAchieved {
            commit_seq,
            requested,
            achieved,
        });
    }
    Ok(())
}
