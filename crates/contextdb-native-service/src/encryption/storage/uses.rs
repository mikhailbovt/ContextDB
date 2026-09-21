//! Native commit markers are local protocol metadata, outside logical archives.
//! Every restored target keeps a fresh instance and records ciphertext imports.

use super::*;
use crate::encryption::keys::uses::{LOCAL_HEAD, LOCAL_SPACE, MAX_CHANGES};

impl NativeStorage {
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
        BEFORE_NATIVE_COMMIT.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
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
