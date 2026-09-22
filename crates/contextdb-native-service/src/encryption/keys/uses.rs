//! Independently retained native ciphertext transitions and commit outcomes.

use std::collections::BTreeSet;

use contextdb_storage::{CommitReceipt, ScanPageRequest};

use super::*;

mod catalog;
mod inventory;
mod journal;
mod publication;
mod reads;
pub use catalog::{
    NativeKeyUseCatalogPage, NativeKeyUseChangesPage, NativeKeyUseOutcome, NativeKeyUseReceipt,
    NativeKeyUseTransaction,
};
pub use inventory::{NativeKeyUseAddressInventory, NativeKeyUseInventory, NativeKeyUseTransition};
#[cfg(test)]
mod tests;

pub(in crate::encryption) use publication::UsePublication;

/// Independently verified bootstrap state, never inferred from directory contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedInstanceState {
    Missing,
    RegisteredOnly,
    Active,
}

pub(super) const HEAD: &[u8] = b"use/head";
const EVENTS: &[u8] = b"use/event/";
const STATES: &[u8] = b"use/state/";
const INSTANCES: &[u8] = b"use/instance/";
const OUTCOMES: &[u8] = b"use/outcome/";
pub(in crate::encryption) const LOCAL_SPACE: &str = "contextdb_native_key_use";
pub(in crate::encryption) const LOCAL_HEAD: &[u8] = b"head";
pub(in crate::encryption) const CHANGES_PER_PAGE: usize = 256;
// Covers the existing two-million-row administrative restore plus its pristine
// target's control rows. This is separate from the new-key allocation bound.
pub(in crate::encryption) const MAX_CHANGES: usize = 2_100_000;
const MAX_EVENT_BYTES: usize = 1024 * 1024;

impl NativeCustodyKeys {
    pub(in crate::encryption) fn budgeted_use_publication(
        &self,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> contextdb_service::ServiceResult<UsePublication<'_>> {
        if !self.tracks_native_use() {
            return Err(crate::unsupported(
                "managed workers require custody version 4",
            ));
        }
        let guard = self
            .writes
            .enter(|| budget.check().map_err(crate::raw_index::budget_error))?;
        self.retirement_frontier().map_err(crate::storage_error)?;
        Ok(UsePublication {
            keys: self,
            _guard: guard,
        })
    }

    pub(super) fn require_registered_instance<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        instance: Uuid,
    ) -> contextdb_storage::Result<()> {
        self.use_state(snapshot, instance).map(|_| ())
    }
}

#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::encryption) struct UseCheckpoint {
    pub sequence: u64,
    pub digest: Option<String>,
}

/// Exact authenticated ciphertext observed before or after a native mutation.
/// It describes a version, not the number of physical or exported copies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyUseVersion {
    /// Immutable key UUID in this custody authority.
    pub key_id: Uuid,
    /// Commitment to the complete authenticated ciphertext envelope.
    pub ciphertext_digest: String,
    /// Commitment to its exact decoded value, without retaining that value.
    pub value_digest: String,
    /// Complete ciphertext envelope length.
    pub ciphertext_bytes: u64,
}

/// One final address transition in a native transaction. Intermediate writes
/// inside that uncommitted transaction are not claimed as accepted versions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyUseChange {
    /// Domain-separated hash of the native keyspace and row key.
    pub address_digest: String,
    /// Version at the transaction's base, or an observed absent address.
    pub before: Option<NativeKeyUseVersion>,
    /// Final staged version; None is a logical deletion, never key erasure.
    pub after: Option<NativeKeyUseVersion>,
}

impl NativeKeyUseChange {
    pub(super) fn validate(&self) -> contextdb_storage::Result<()> {
        valid_digest(&self.address_digest)?;
        for version in self.before.iter().chain(self.after.iter()) {
            if version.key_id.is_nil()
                || !(64..=(MAX_VALUE_BYTES + 64) as u64).contains(&version.ciphertext_bytes)
            {
                return Err(failure("native key-use version shape differs"));
            }
            valid_digest(&version.ciphertext_digest)?;
            valid_digest(&version.value_digest)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::encryption) struct LocalMarker {
    pub instance: Uuid,
    pub native_sequence: u64,
    pub usage: Option<UseCheckpoint>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preparation {
    transaction: Uuid,
    previous: LocalMarker,
    pages: u32,
    changes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingUse {
    preparation: Preparation,
    checkpoint: UseCheckpoint,
}

impl PendingUse {
    fn expected(&self) -> contextdb_storage::Result<LocalMarker> {
        Ok(LocalMarker {
            instance: self.preparation.previous.instance,
            native_sequence: self
                .preparation
                .previous
                .native_sequence
                .checked_add(1)
                .ok_or_else(|| failure("native key-use sequence exhausted"))?,
            usage: Some(self.checkpoint.clone()),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstanceState {
    revision: u64,
    accepted: UseCheckpoint,
    marker: LocalMarker,
    pending: Option<PendingUse>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum UseOperation {
    Register {
        instance: Uuid,
    },
    Page {
        transaction: Uuid,
        index: u32,
        changes: Vec<NativeKeyUseChange>,
    },
    Prepare {
        preparation: Preparation,
    },
    Complete {
        prepared: UseCheckpoint,
        instance: Uuid,
        committed: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UseEvent {
    checkpoint: UseCheckpoint,
    previous_digest: Option<String>,
    change: UseOperation,
}

impl UseEvent {
    fn digest(&self) -> contextdb_storage::Result<String> {
        Ok(crate::digest_bytes(&encode(&(
            "contextdb/native-key-use-event/v1",
            self.checkpoint.sequence,
            &self.previous_digest,
            &self.change,
        ))?))
    }
}

impl NativeCustodyKeys {
    pub(in crate::encryption) fn tracks_native_use(&self) -> bool {
        self.identity.version >= 4
    }

    pub(in crate::encryption) fn use_publication(
        &self,
    ) -> contextdb_storage::Result<UsePublication<'_>> {
        if !self.tracks_native_use() {
            return Err(failure(
                "native key-use tracking requires custody version 4",
            ));
        }
        let guard = self
            .writes
            .enter(|| Ok(()))
            .map_err(|_| failure("custody publication admission unavailable"))?;
        self.retirement_frontier()?;
        Ok(UsePublication {
            keys: self,
            _guard: guard,
        })
    }

    pub(crate) fn observe_archived_version(
        &self,
        space: &Keyspace,
        key: &[u8],
        value: &[u8],
    ) -> contextdb_storage::Result<NativeKeyUseVersion> {
        self.observe_use_version(space, key, value, None)
    }

    pub(in crate::encryption) fn observe_use_version(
        &self,
        space: &Keyspace,
        key: &[u8],
        value: &[u8],
        pending: Option<&PendingKeys>,
    ) -> contextdb_storage::Result<NativeKeyUseVersion> {
        let plaintext = self.open_value(space, key, value, pending)?;
        let id = Uuid::from_slice(&value[VALUE_MAGIC.len()..VALUE_MAGIC.len() + 16])
            .map_err(|_| failure("native key-use ciphertext UUID differs"))?;
        Ok(NativeKeyUseVersion {
            key_id: id,
            ciphertext_digest: crate::digest_bytes(value),
            value_digest: crate::digest_bytes(&plaintext),
            ciphertext_bytes: value.len() as u64,
        })
    }

    pub(in crate::encryption) fn seal_local_marker(
        &self,
        marker: &LocalMarker,
    ) -> contextdb_storage::Result<Vec<u8>> {
        self.seal_use(LOCAL_HEAD, &encode(marker)?, "native-marker")
    }

    pub(in crate::encryption) fn read_local_marker<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> contextdb_storage::Result<LocalMarker> {
        let space = Keyspace::new(LOCAL_SPACE)?;
        let rows = snapshot.scan_prefix_page(
            &space,
            ScanPageRequest {
                prefix: b"",
                start_after: None,
                max_entries: 2,
                max_bytes: MAX_EVENT_BYTES,
            },
        )?;
        if rows.entries.len() != 1
            || rows.entries[0].key != LOCAL_HEAD
            || rows.continuation.is_some()
        {
            return Err(failure(
                "native key-use marker is missing or has unknown rows",
            ));
        }
        let marker: LocalMarker =
            decode(&self.open_use(LOCAL_HEAD, &rows.entries[0].value, "native-marker")?)?;
        if marker.instance.is_nil()
            || marker.native_sequence == 0
            || marker.native_sequence != snapshot.sequence()
        {
            return Err(failure(
                "native key-use marker differs from physical commit",
            ));
        }
        if let Some(receipt) = &marker.usage {
            validate_checkpoint(receipt, false)?;
        }
        Ok(marker)
    }

    fn seal_use(
        &self,
        key: &[u8],
        plaintext: &[u8],
        domain: &str,
    ) -> contextdb_storage::Result<Vec<u8>> {
        seal(
            &self.master.0,
            &encode(&("contextdb/native-key-use/v1", &self.identity, domain, key))?,
            plaintext,
        )
    }

    fn open_use(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        domain: &str,
    ) -> contextdb_storage::Result<Zeroizing<Vec<u8>>> {
        if ciphertext.len() > MAX_EVENT_BYTES + NONCE_BYTES + TAG_BYTES {
            return Err(failure("native key-use record exceeds its bound"));
        }
        open(
            &self.master.0,
            &encode(&("contextdb/native-key-use/v1", &self.identity, domain, key))?,
            ciphertext,
        )
    }
}

pub(super) fn genesis(
    identity: &Identity,
    master: &CustodyMasterKey,
) -> contextdb_storage::Result<Vec<u8>> {
    seal(
        &master.0,
        &encode(&("contextdb/native-key-use/v1", identity, "journal", HEAD))?,
        &encode(&UseCheckpoint::default())?,
    )
}

fn event_key(sequence: u64) -> Vec<u8> {
    format!("use/event/{sequence:020}").into_bytes()
}
fn state_key(instance: Uuid) -> Vec<u8> {
    format!("use/state/{instance}").into_bytes()
}
fn outcome_key(sequence: u64) -> Vec<u8> {
    format!("use/outcome/{sequence:020}").into_bytes()
}
fn instance_key(instance: Uuid, revision: u64) -> Vec<u8> {
    format!("use/instance/{instance}/{revision:020}").into_bytes()
}
fn valid_digest(digest: &str) -> contextdb_storage::Result<()> {
    blake3::Hash::from_hex(digest)
        .map(|_| ())
        .map_err(|_| failure("native key-use digest is invalid"))
}
fn validate_checkpoint(checkpoint: &UseCheckpoint, empty: bool) -> contextdb_storage::Result<()> {
    if (checkpoint.sequence == 0) != checkpoint.digest.is_none()
        || (!empty && checkpoint.sequence == 0)
    {
        return Err(failure("native key-use checkpoint is invalid"));
    }
    if let Some(digest) = &checkpoint.digest {
        valid_digest(digest)?;
    }
    Ok(())
}
