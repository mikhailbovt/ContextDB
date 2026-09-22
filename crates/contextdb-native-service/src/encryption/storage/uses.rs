//! Native commit markers are local protocol metadata, outside logical archives.
//! Every restored target keeps a fresh instance and records ciphertext imports.

use super::*;
use crate::encryption::keys::uses::{LOCAL_HEAD, LOCAL_SPACE, MAX_CHANGES};

impl NativeStorage {
    pub(crate) fn open_managed_archive(
        path: &Path,
        keys: Arc<NativeCustodyKeys>,
        instance: uuid::Uuid,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> contextdb_service::ServiceResult<Self> {
        use crate::{integrity, raw_index::budget_error, storage_error};
        budget.check().map_err(budget_error)?;
        let publication = keys.budgeted_use_publication(budget)?;
        let storage = Self {
            inner: FjallStorage::open(path).map_err(storage_error)?,
            keys: Some(keys.clone()),
        };
        let snapshot = storage
            .inner
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if storage
            .inner
            .physical_keyspace_names()
            .iter()
            .any(|name| name == LOCAL_SPACE)
        {
            let marker = keys.read_local_marker(&snapshot).map_err(storage_error)?;
            if marker.instance != instance {
                return Err(integrity(
                    "managed archive directory belongs to another native instance",
                ));
            }
            publication
                .reconcile(&storage.inner)
                .map_err(storage_error)?;
        } else {
            if snapshot.sequence() != 0
                || storage
                    .inner
                    .physical_keyspace_names()
                    .iter()
                    .any(|name| name != contextdb_storage_fjall::FJALL_INTERNAL_META_KEYSPACE)
            {
                return Err(integrity(
                    "managed archive directory lacks its native-use marker",
                ));
            }
            let marker = publication.register_managed(instance, budget)?;
            #[cfg(test)]
            AFTER_MANAGED_REGISTRATION.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
            let space = Keyspace::new(LOCAL_SPACE).map_err(storage_error)?;
            let mut tx = storage.inner.begin_write().map_err(storage_error)?;
            tx.put(
                &space,
                LOCAL_HEAD.to_vec(),
                keys.seal_local_marker(&marker).map_err(storage_error)?,
            )
            .map_err(storage_error)?;
            budget.check().map_err(budget_error)?;
            let receipt = tx.commit(Durability::Sync).map_err(storage_error)?;
            if receipt.sequence != marker.native_sequence {
                return Err(integrity("managed archive bootstrap sequence differs"));
            }
            crate::require_sync(receipt.durability)?;
        }
        Ok(storage)
    }

    pub(crate) fn registered_instance(&self) -> Result<uuid::Uuid> {
        let keys = self
            .keys
            .as_ref()
            .filter(|keys| keys.tracks_native_use())
            .ok_or_else(|| failure("archive jobs require registered native-use custody"))?;
        Ok(keys.use_publication()?.reconcile(&self.inner)?.instance)
    }

    pub(crate) fn is_protocol_genesis(&self) -> Result<bool> {
        let Some(keys) = self.keys.as_ref().filter(|keys| keys.tracks_native_use()) else {
            return Ok(false);
        };
        let marker = keys.use_publication()?.reconcile(&self.inner)?;
        Ok(marker.native_sequence == 1
            && marker.usage.is_none()
            && self.inner.physical_keyspace_names().iter().all(|name| {
                [
                    LOCAL_SPACE,
                    contextdb_storage_fjall::FJALL_INTERNAL_META_KEYSPACE,
                ]
                .contains(&name.as_str())
            }))
    }

    pub(super) fn initialize_native_use(&self) -> Result<()> {
        let Some(keys) = self.keys.as_ref().filter(|keys| keys.tracks_native_use()) else {
            return Ok(());
        };
        let publication = keys.use_publication()?;
        if self
            .inner
            .physical_keyspace_names()
            .iter()
            .any(|name| name == LOCAL_SPACE)
        {
            publication.reconcile(&self.inner)?;
            return Ok(());
        }
        if self.inner.head_sequence()? != 0
            || self
                .inner
                .physical_keyspace_names()
                .iter()
                .any(|name| name != contextdb_storage_fjall::FJALL_INTERNAL_META_KEYSPACE)
        {
            return Err(failure(
                "native key-use tracking requires explicit migration of existing storage",
            ));
        }
        let marker = publication.register()?;
        let space = Keyspace::new(LOCAL_SPACE)?;
        let mut tx = self.inner.begin_write()?;
        tx.put(
            &space,
            LOCAL_HEAD.to_vec(),
            keys.seal_local_marker(&marker)?,
        )?;
        let receipt = tx.commit(Durability::Sync)?;
        if receipt.sequence != marker.native_sequence || receipt.durability != Durability::Sync {
            return Err(failure("native key-use instance was not synchronized"));
        }
        Ok(())
    }

    pub(super) fn reconcile_native_use(&self) -> Result<()> {
        if let Some(keys) = self.keys.as_ref().filter(|keys| keys.tracks_native_use()) {
            keys.use_publication()?.reconcile(&self.inner)?;
        }
        Ok(())
    }

    pub(crate) fn protocol_keyspaces(&self) -> Result<Vec<String>> {
        self.reconcile_native_use()?;
        Ok(
            if self
                .keys
                .as_ref()
                .is_some_and(|keys| keys.tracks_native_use())
            {
                vec![LOCAL_SPACE.into()]
            } else {
                Vec::new()
            },
        )
    }
}

#[cfg(test)]
type RegistrationHook = Box<dyn FnOnce() -> contextdb_service::ServiceResult<()>>;
#[cfg(test)]
thread_local! {
    pub(crate) static AFTER_MANAGED_REGISTRATION: std::cell::RefCell<Option<RegistrationHook>> = const { std::cell::RefCell::new(None) };
}

impl NativeTransaction<'_> {
    pub(super) fn track_use_change(
        &mut self,
        space: &Keyspace,
        key: &[u8],
        after: Option<&[u8]>,
    ) -> Result<()> {
        let Some(keys) = self.keys.as_ref().filter(|keys| keys.tracks_native_use()) else {
            return Ok(());
        };
        if space.as_str() == LOCAL_SPACE {
            return Err(failure(
                "native key-use metadata is owned by the commit protocol",
            ));
        }
        let address_digest = address(space, key);
        let before = if let Some(previous) = self.changes.get(&address_digest) {
            previous.before.clone()
        } else {
            if self.changes.len() >= MAX_CHANGES {
                return Err(failure("native key-use transition exceeds its row bound"));
            }
            self.inner
                .get(space, key)?
                .map(|value| keys.observe_use_version(space, key, &value, None))
                .transpose()?
        };
        let after = after
            .map(|value| keys.observe_use_version(space, key, value, Some(&self.pending)))
            .transpose()?;
        self.changes.insert(
            address_digest.clone(),
            NativeKeyUseChange {
                address_digest,
                before,
                after,
            },
        );
        Ok(())
    }

    pub(super) fn commit_with_use(mut self, durability: Durability) -> Result<CommitReceipt> {
        if durability != Durability::Sync {
            return Err(failure(
                "tracked native publication requires Sync durability",
            ));
        }
        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| failure("native key-use authority absent"))?
            .clone();
        let publication = keys.use_publication()?;
        keys.require_retirement_frontier(self.retirement.as_ref())?;
        let previous = publication.reconcile(&self.owner.inner)?;
        if self.inner.sequence() != previous.native_sequence {
            return Err(StorageError::WriteConflict {
                base: self.inner.sequence(),
                head: previous.native_sequence,
            });
        }
        let marker = publication.prepare(&previous, &self.changes, &self.pending)?;
        self.inner.put(
            &Keyspace::new(LOCAL_SPACE)?,
            LOCAL_HEAD.to_vec(),
            keys.seal_local_marker(&marker)?,
        )?;
        #[cfg(test)]
        BEFORE_NATIVE_COMMIT.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        let receipt = self.inner.commit(durability)?;
        #[cfg(test)]
        AFTER_NATIVE_COMMIT.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        publication.acknowledge(&marker, &receipt)?;
        Ok(receipt)
    }
}

#[cfg(test)]
thread_local! {
    pub(in crate::encryption) static AFTER_NATIVE_COMMIT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
