//! Acknowledged snapshots do not join the custody writer queue. Only a visible,
//! unacknowledged native commit requires recovery before it can be disclosed.

use contextdb_storage_fjall::FjallStorage;

use super::*;

#[derive(Eq, PartialEq)]
enum Admission {
    Accepted,
    AcceptedWithPending,
    RecoveryRequired,
}

impl NativeCustodyKeys {
    pub(in crate::encryption) fn admit_use_snapshot<S: ReadSnapshot>(
        &self,
        storage: &FjallStorage,
        snapshot: &S,
    ) -> contextdb_storage::Result<()> {
        let admission = self.inspect_use_snapshot(storage, snapshot)?;
        if admission == Admission::Accepted {
            return Ok(());
        }
        let guard = self
            .writes
            .try_enter()
            .map_err(|_| failure("custody recovery admission unavailable"))?;
        let Some(guard) = guard else {
            return if admission == Admission::AcceptedWithPending {
                Ok(())
            } else {
                Err(failure(
                    "native commit acknowledgement is pending; retry the read",
                ))
            };
        };
        let publication = UsePublication {
            keys: self,
            _guard: guard,
        };
        publication.reconcile(storage)?;
        if self.inspect_use_snapshot(storage, snapshot)? != Admission::Accepted {
            return Err(failure("native snapshot has no recovered acknowledgement"));
        }
        Ok(())
    }

    fn inspect_use_snapshot<S: ReadSnapshot>(
        &self,
        storage: &FjallStorage,
        snapshot: &S,
    ) -> contextdb_storage::Result<Admission> {
        let selected = self.read_local_marker(snapshot)?;
        // Preparation precedes native publication. Read authority after selecting
        // the native view, then current native state after authority to distinguish
        // a legitimate older snapshot from a rollback of the physical store.
        let authority = self.engine.begin_read(SnapshotSelector::Latest)?;
        let head = self.use_head(&authority)?;
        let state = self.use_state(&authority, selected.instance)?;
        let current = self.read_local_marker(&storage.begin_read(SnapshotSelector::Latest)?)?;
        if current.instance != selected.instance
            || current.native_sequence < selected.native_sequence
            || current.native_sequence < state.marker.native_sequence
            || (current.native_sequence == state.marker.native_sequence && current != state.marker)
        {
            return Err(failure(
                "native key-use current storage is behind retained acceptance",
            ));
        }
        if current.native_sequence > state.marker.native_sequence
            && current
                .usage
                .as_ref()
                .is_none_or(|usage| usage.sequence <= head.sequence)
            && state
                .pending
                .as_ref()
                .map(PendingUse::expected)
                .transpose()?
                .as_ref()
                != Some(&current)
        {
            return Err(failure(
                "native key-use current marker has no retained preparation",
            ));
        }
        let accepted = if let Some(checkpoint) = &selected.usage {
            let event = self.use_event(&authority, checkpoint.sequence)?;
            let UseOperation::Prepare { preparation } = event.change else {
                return Err(failure("native snapshot marker is not a preparation"));
            };
            let pending = PendingUse {
                preparation,
                checkpoint: checkpoint.clone(),
            };
            if event.checkpoint != *checkpoint || pending.expected()? != selected {
                return Err(failure("native snapshot preparation binding differs"));
            }
            let key = outcome_key(checkpoint.sequence);
            if let Some(bytes) = authority.get(&self.rows, &key)? {
                let outcome: UseCheckpoint = decode(&self.open_use(&key, &bytes, "journal")?)?;
                let event = self.use_event(&authority, outcome.sequence)?;
                if outcome.sequence <= checkpoint.sequence
                    || outcome.sequence > head.sequence
                    || event.checkpoint != outcome
                    || event.change
                        != (UseOperation::Complete {
                            prepared: checkpoint.clone(),
                            instance: selected.instance,
                            committed: true,
                        })
                {
                    return Err(failure("native snapshot has no committed outcome"));
                }
                true
            } else {
                if state.pending.as_ref() != Some(&pending) {
                    return Err(failure(
                        "native snapshot outcome is missing rather than pending",
                    ));
                }
                false
            }
        } else {
            let key = instance_key(selected.instance, 1);
            let bytes = authority
                .get(&self.rows, &key)?
                .ok_or_else(|| failure("native snapshot registration is absent"))?;
            let registered: UseCheckpoint = decode(&self.open_use(&key, &bytes, "journal")?)?;
            let event = self.use_event(&authority, registered.sequence)?;
            if selected.native_sequence != 1
                || event.checkpoint != registered
                || event.change
                    != (UseOperation::Register {
                        instance: selected.instance,
                    })
            {
                return Err(failure("native snapshot registration differs"));
            }
            true
        };
        Ok(if !accepted {
            Admission::RecoveryRequired
        } else if state.pending.is_some() {
            Admission::AcceptedWithPending
        } else {
            Admission::Accepted
        })
    }
}
