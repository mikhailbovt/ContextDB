use contextdb_storage_fjall::FjallStorage;

use super::*;

/// The same authority queue will fence lifecycle changes through native Sync.
/// Its guard stays held across preparation, native publication and acknowledgement.
pub(in crate::encryption) struct UsePublication<'a> {
    pub(super) keys: &'a NativeCustodyKeys,
    pub(super) _guard: crate::publication::PublicationGuard<'a>,
}

impl UsePublication<'_> {
    pub(in crate::encryption) fn register(&self) -> contextdb_storage::Result<LocalMarker> {
        self.register_instance(contextdb_core::ObservationId::new().as_uuid())
    }

    fn register_instance(&self, instance: Uuid) -> contextdb_storage::Result<LocalMarker> {
        let mut tx = self.keys.engine.begin_write()?;
        let mut head = self.keys.use_head(&tx)?;
        if tx.get(&self.keys.rows, &state_key(instance))?.is_some() {
            return Err(failure("native key-use instance already exists"));
        }
        let accepted =
            self.keys
                .append_use_event(&mut tx, &mut head, UseOperation::Register { instance })?;
        let marker = LocalMarker {
            instance,
            native_sequence: 1,
            usage: None,
        };
        self.keys.put_use_state(
            &mut tx,
            &InstanceState {
                revision: 1,
                accepted,
                marker: marker.clone(),
                pending: None,
                sealed: None,
            },
        )?;
        synchronized(tx.commit(Durability::Sync)?)?;
        Ok(marker)
    }

    pub(in crate::encryption) fn register_managed(
        &self,
        instance: Uuid,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> contextdb_service::ServiceResult<LocalMarker> {
        use contextdb_service::{ErrorCode, ServiceError};
        let state = self.keys.managed_instance_state(instance, budget)?;
        match state {
            ManagedInstanceState::Missing => self
                .register_instance(instance)
                .map_err(crate::storage_error),
            ManagedInstanceState::RegisteredOnly => Ok(LocalMarker {
                instance,
                native_sequence: 1,
                usage: None,
            }),
            ManagedInstanceState::Active => Err(ServiceError::new(
                ErrorCode::EvidenceRequired,
                "managed archive worker already has native history; recover its original directory",
                false,
            )),
            ManagedInstanceState::Sealed => Err(ServiceError::new(
                ErrorCode::EvidenceRequired,
                "managed archive worker is sealed; a verified replacement is required",
                false,
            )),
        }
    }

    pub(in crate::encryption) fn reconcile(
        &self,
        storage: &FjallStorage,
    ) -> contextdb_storage::Result<LocalMarker> {
        let snapshot = storage.begin_read(SnapshotSelector::Latest)?;
        let marker = self.keys.read_local_marker(&snapshot)?;
        let authority = self.keys.engine.begin_read(SnapshotSelector::Latest)?;
        self.keys.use_head(&authority)?;
        let state = self.keys.use_state(&authority, marker.instance)?;
        if state.sealed.is_some() {
            return Err(failure("native archive worker is permanently sealed"));
        }
        let Some(pending) = &state.pending else {
            if marker != state.marker {
                return Err(failure(
                    "native key-use marker is behind or outside retained acceptance",
                ));
            }
            return Ok(marker);
        };
        let committed = if marker == pending.expected()? {
            true
        } else if marker == state.marker {
            false
        } else {
            return Err(failure(
                "native key-use recovery cannot identify the committed transaction",
            ));
        };
        // A prior Sync failure may have made rows visible without durable ack.
        // Force the existing journal to stable storage before recording either
        // outcome; do not add a compensating native transaction or rewrite data.
        storage.synchronize()?;
        drop(authority);
        self.finish(&marker, committed)?;
        Ok(marker)
    }

    pub(in crate::encryption) fn prepare(
        &self,
        previous: &LocalMarker,
        changes: &BTreeMap<String, NativeKeyUseChange>,
        pending: &PendingKeys,
    ) -> contextdb_storage::Result<LocalMarker> {
        if changes.len() > MAX_CHANGES {
            return Err(failure("native key-use transition exceeds its row bound"));
        }
        let mut tx = self.keys.engine.begin_write()?;
        let mut head = self.keys.use_head(&tx)?;
        let mut state = self.keys.use_state(&tx, previous.instance)?;
        if state.marker != *previous || state.pending.is_some() || state.sealed.is_some() {
            return Err(failure(
                "native key-use preparation requires its reconciled base",
            ));
        }
        if !pending.is_empty() {
            self.keys.publish_key_versions(&mut tx, pending)?;
        }
        for (address, change) in changes {
            if address != &change.address_digest {
                return Err(failure("native key-use transition address differs"));
            }
            self.keys.validate_use_keys(&tx, change)?;
            for version in change.before.iter().chain(change.after.iter()) {
                drop(self.keys.admit_key(version.key_id)?);
            }
        }
        let transaction = contextdb_core::ObservationId::new().as_uuid();
        let mut pages = 0_u32;
        let mut rows = Vec::with_capacity(CHANGES_PER_PAGE);
        for change in changes.values() {
            rows.push(change.clone());
            if rows.len() == CHANGES_PER_PAGE {
                self.keys.append_use_event(
                    &mut tx,
                    &mut head,
                    UseOperation::Page {
                        transaction,
                        index: pages,
                        changes: std::mem::take(&mut rows),
                    },
                )?;
                pages += 1;
            }
        }
        if !rows.is_empty() {
            self.keys.append_use_event(
                &mut tx,
                &mut head,
                UseOperation::Page {
                    transaction,
                    index: pages,
                    changes: rows,
                },
            )?;
            pages += 1;
        }
        let preparation = Preparation {
            transaction,
            previous: previous.clone(),
            pages,
            changes: changes.len() as u64,
        };
        let accepted = self.keys.append_use_event(
            &mut tx,
            &mut head,
            UseOperation::Prepare {
                preparation: preparation.clone(),
            },
        )?;
        let pending = PendingUse {
            preparation,
            checkpoint: accepted.clone(),
        };
        let marker = pending.expected()?;
        state.pending = Some(pending);
        journal::advance_state(&mut state, &accepted)?;
        self.keys.put_use_state(&mut tx, &state)?;
        synchronized(tx.commit(Durability::Sync)?)?;
        Ok(marker)
    }

    pub(in crate::encryption) fn acknowledge(
        &self,
        marker: &LocalMarker,
        receipt: &CommitReceipt,
    ) -> contextdb_storage::Result<()> {
        if receipt.durability != Durability::Sync || receipt.sequence != marker.native_sequence {
            return Err(failure(
                "native key-use acknowledgement is not its synchronized commit",
            ));
        }
        self.finish(marker, true)
    }

    fn finish(&self, marker: &LocalMarker, committed: bool) -> contextdb_storage::Result<()> {
        let mut tx = self.keys.engine.begin_write()?;
        let mut head = self.keys.use_head(&tx)?;
        let mut state = self.keys.use_state(&tx, marker.instance)?;
        let pending = state
            .pending
            .take()
            .ok_or_else(|| failure("native key-use outcome has no pending preparation"))?;
        let expected = if committed {
            pending.expected()?
        } else {
            state.marker.clone()
        };
        if *marker != expected {
            return Err(failure("native key-use outcome differs from its marker"));
        }
        let accepted = self.keys.append_use_event(
            &mut tx,
            &mut head,
            UseOperation::Complete {
                prepared: pending.checkpoint.clone(),
                instance: marker.instance,
                committed,
            },
        )?;
        let outcome = outcome_key(pending.checkpoint.sequence);
        if tx.get(&self.keys.rows, &outcome)?.is_some() {
            return Err(failure("native key-use outcome already exists"));
        }
        tx.put(
            &self.keys.rows,
            outcome.clone(),
            self.keys
                .seal_use(&outcome, &encode(&accepted)?, "journal")?,
        )?;
        state.marker = expected;
        journal::advance_state(&mut state, &accepted)?;
        self.keys.put_use_state(&mut tx, &state)?;
        synchronized(tx.commit(Durability::Sync)?)
    }
}

fn synchronized(receipt: CommitReceipt) -> contextdb_storage::Result<()> {
    if receipt.durability != Durability::Sync {
        return Err(failure("native key-use journal was not synchronized"));
    }
    Ok(())
}
