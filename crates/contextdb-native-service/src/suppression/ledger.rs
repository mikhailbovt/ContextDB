//! Independently retained, append-only revocation authority. Native backups never
//! contain this store. Its current directory and identity are host-owned recovery
//! inputs; restoring an old copy of both authorities is outside this profile.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use contextdb_core::{ContentDigest, ObservationId};
use contextdb_recall::QueryBudget;
use contextdb_storage_fjall::{FJALL_INTERNAL_META_KEYSPACE, FjallStorage};
use uuid::Uuid;

use super::*;

mod record_sources;
mod removal;
pub(crate) use record_sources::{RecordSourceControl, RecordSourcesCheckpoint};
pub(crate) use removal::{RemovalCheckpoint, RemovalIntent};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u16,
    authority: Uuid,
    database: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    pub epoch: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Denial {
    pub workspace: String,
    pub epoch: u64,
    pub event_id: ObservationId,
    pub event_digest: ContentDigest,
    previous: String,
    pub digest: String,
}

impl Denial {
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            epoch: self.epoch,
            digest: self.digest.clone(),
        }
    }
}

/// Current local suppression authority, retained separately from native backups.
///
/// Keep the directory and [`Self::authority_id`] in the host recovery inventory.
/// `open` never substitutes a fresh ledger when that authority is unavailable.
/// Local filesystem custody is required; this is not a remote anti-rollback or
/// hardware monotonic-counter service.
pub struct NativeSuppressionLedger {
    engine: FjallStorage,
    rows: Keyspace,
    identity: Identity,
    pub(crate) path: PathBuf,
    writes: publication::PublicationQueue,
}

impl fmt::Debug for NativeSuppressionLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeSuppressionLedger")
            .finish_non_exhaustive()
    }
}

impl NativeSuppressionLedger {
    /// Create a new authority in a new directory. An existing path is rejected.
    pub fn create(path: impl AsRef<Path>, database_id: &str) -> ServiceResult<Arc<Self>> {
        validate_identifier(database_id, "suppression database ID")?;
        std::fs::create_dir(path.as_ref())
            .map_err(|_| integrity("suppression authority requires a new directory"))?;
        let engine = FjallStorage::open(path.as_ref()).map_err(storage_error)?;
        let rows = keyspace("contextdb_suppression")?;
        let identity = Identity {
            version: 3,
            authority: ObservationId::new().as_uuid(),
            database: digest_bytes(database_id.as_bytes()),
        };
        let mut tx = engine.begin_write().map_err(storage_error)?;
        tx.put(&rows, b"identity".to_vec(), encode(&identity)?)
            .map_err(storage_error)?;
        tx.put(
            &rows,
            removal::HEAD.to_vec(),
            encode(&removal::genesis(&identity)?)?,
        )
        .map_err(storage_error)?;
        tx.put(
            &rows,
            record_sources::HEAD.to_vec(),
            encode(&record_sources::genesis(&identity)?)?,
        )
        .map_err(storage_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Self::finish_open(engine, rows, identity, path.as_ref())
    }

    /// Reopen the exact independently retained authority; missing data, a new
    /// identity or another database never becomes an empty replacement ledger.
    pub fn open(
        path: impl AsRef<Path>,
        database_id: &str,
        authority: Uuid,
    ) -> ServiceResult<Arc<Self>> {
        if !path.as_ref().is_dir() {
            return Err(integrity("current suppression authority is unavailable"));
        }
        let engine = FjallStorage::open(path.as_ref()).map_err(storage_error)?;
        let rows = keyspace("contextdb_suppression")?;
        let snapshot = engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let identity: Identity = decode(
            &snapshot
                .get(&rows, b"identity")
                .map_err(storage_error)?
                .ok_or_else(|| integrity("suppression identity is missing"))?,
            "suppression identity",
        )?;
        if !matches!(identity.version, 1..=3)
            || identity.authority != authority
            || identity.database != digest_bytes(database_id.as_bytes())
        {
            return Err(integrity("current suppression authority binding differs"));
        }
        drop(snapshot);
        Self::finish_open(engine, rows, identity, path.as_ref())
    }

    fn finish_open(
        engine: FjallStorage,
        rows: Keyspace,
        identity: Identity,
        path: &Path,
    ) -> ServiceResult<Arc<Self>> {
        let ledger = Self {
            engine,
            rows,
            identity,
            path: path
                .canonicalize()
                .map_err(|_| integrity("suppression path is unavailable"))?,
            writes: Default::default(),
        };
        ledger.verify()?;
        Ok(Arc::new(ledger))
    }

    /// Stable authority identity, suitable for the external recovery inventory.
    #[must_use]
    pub fn authority_id(&self) -> Uuid {
        self.identity.authority
    }

    pub(crate) fn require_database(&self, database: &str) -> ServiceResult<()> {
        if self.identity.database != digest_bytes(database.as_bytes()) {
            return Err(integrity(
                "suppression authority belongs to another database",
            ));
        }
        Ok(())
    }

    pub(super) fn genesis(&self, workspace: &str) -> ServiceResult<Checkpoint> {
        Ok(Checkpoint {
            epoch: 0,
            digest: canonical_digest(&(&self.identity, workspace))?,
        })
    }

    fn head<S: ReadSnapshot>(&self, snapshot: &S, workspace: &str) -> ServiceResult<Checkpoint> {
        snapshot
            .get(&self.rows, &head_key(workspace))
            .map_err(storage_error)?
            .map(|bytes| decode(&bytes, "suppression head"))
            .unwrap_or_else(|| self.genesis(workspace))
    }

    pub(super) fn current(&self, workspace: &str) -> ServiceResult<Checkpoint> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.head(&snapshot, workspace)
    }

    pub(super) fn entry(&self, workspace: &str, epoch: u64) -> ServiceResult<Denial> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.read_entry(&snapshot, workspace, epoch)
    }

    fn read_entry<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        epoch: u64,
    ) -> ServiceResult<Denial> {
        let entry: Denial = decode(
            &snapshot
                .get(&self.rows, &event_key(workspace, epoch))
                .map_err(storage_error)?
                .ok_or_else(|| integrity("accepted suppression entry is missing"))?,
            "suppression entry",
        )?;
        let mut unsigned = entry.clone();
        unsigned.digest.clear();
        if entry.workspace != workspace
            || entry.epoch != epoch
            || epoch == 0
            || entry.digest != canonical_digest(&(&self.identity, &unsigned))?
        {
            return Err(integrity("suppression entry binding differs"));
        }
        Ok(entry)
    }

    pub(super) fn denied(&self, workspace: &str, id: ObservationId) -> ServiceResult<bool> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        Ok(snapshot
            .get(&self.rows, &denied_key(workspace, id))
            .map_err(storage_error)?
            .is_some()
            || self.removal_denies(&snapshot, workspace, id)?)
    }

    pub(super) fn deny(
        &self,
        workspace: &str,
        id: ObservationId,
        digest: ContentDigest,
        expected: &Checkpoint,
        budget: &QueryBudget,
    ) -> ServiceResult<Denial> {
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        let head = self.head(&tx, workspace)?;
        if head != *expected {
            return Err(pending());
        }
        if let Some(bytes) = tx
            .get(&self.rows, &denied_key(workspace, id))
            .map_err(storage_error)?
        {
            let epoch: u64 = decode(&bytes, "suppression membership")?;
            let entry = self.read_entry(&tx, workspace, epoch)?;
            if entry.event_id != id || entry.event_digest != digest {
                return Err(integrity("suppressed source identity was reused"));
            }
            return Ok(entry);
        }
        let mut entry = Denial {
            workspace: workspace.into(),
            epoch: head
                .epoch
                .checked_add(1)
                .ok_or_else(|| exhausted("suppression epoch overflow"))?,
            event_id: id,
            event_digest: digest,
            previous: head.digest,
            digest: String::new(),
        };
        entry.digest = canonical_digest(&(&self.identity, &entry))?;
        tx.put(
            &self.rows,
            event_key(workspace, entry.epoch),
            encode(&entry)?,
        )
        .map_err(storage_error)?;
        tx.put(
            &self.rows,
            head_key(workspace),
            encode(&entry.checkpoint())?,
        )
        .map_err(storage_error)?;
        tx.put(&self.rows, denied_key(workspace, id), encode(&entry.epoch)?)
            .map_err(storage_error)?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(entry)
    }

    pub(super) fn batch(
        &self,
        workspace: &str,
        after: &Checkpoint,
        limit: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<Denial>> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let current = self.head(&snapshot, workspace)?;
        let expected = if after.epoch == 0 {
            self.genesis(workspace)?
        } else {
            self.read_entry(&snapshot, workspace, after.epoch)?
                .checkpoint()
        };
        if *after != expected || after.epoch > current.epoch {
            return Err(integrity(
                "applied suppression checkpoint is not an authority prefix",
            ));
        }
        let mut entries = Vec::new();
        let mut previous = after.clone();
        for _ in 0..limit {
            if previous.epoch == current.epoch {
                break;
            }
            let entry = self.read_entry(&snapshot, workspace, previous.epoch + 1)?;
            budget
                .charge(1, encode(&entry)?.len() as u64)
                .map_err(budget_error)?;
            if entry.previous != previous.digest {
                return Err(integrity("suppression prefix is discontinuous"));
            }
            previous = entry.checkpoint();
            entries.push(entry);
        }
        Ok(entries)
    }

    fn verify(&self) -> ServiceResult<()> {
        let allowed = [self.rows.as_str(), FJALL_INTERNAL_META_KEYSPACE];
        if self
            .engine
            .physical_keyspace_names()
            .iter()
            .any(|name| !allowed.contains(&name.as_str()))
        {
            return Err(integrity(
                "suppression authority contains an unknown keyspace",
            ));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let mut expected = BTreeMap::from([(b"identity".to_vec(), encode(&self.identity)?)]);
        self.verify_removal_ledger(&snapshot, &mut expected)?;
        self.verify_record_source_ledger(&snapshot, &mut expected)?;
        for row in snapshot
            .scan_prefix(&self.rows, b"head/")
            .map_err(storage_error)?
        {
            let workspace = std::str::from_utf8(&row.key[b"head/".len()..])
                .map_err(|_| integrity("suppression workspace is invalid"))?;
            if blake3::Hash::from_hex(workspace).is_err() {
                return Err(integrity("suppression workspace digest is invalid"));
            }
            let head: Checkpoint = decode(&row.value, "suppression head")?;
            let mut previous = self.genesis(workspace)?;
            for epoch in 1..=head.epoch {
                let entry = self.read_entry(&snapshot, workspace, epoch)?;
                if entry.previous != previous.digest
                    || expected
                        .insert(denied_key(workspace, entry.event_id), encode(&epoch)?)
                        .is_some()
                {
                    return Err(integrity("suppression chain repeats or skips a source"));
                }
                previous = entry.checkpoint();
                expected.insert(event_key(workspace, epoch), encode(&entry)?);
            }
            if head.epoch == 0 || previous != head {
                return Err(integrity("suppression terminal checkpoint differs"));
            }
            expected.insert(row.key, row.value);
        }
        let actual = snapshot
            .scan_prefix(&self.rows, b"")
            .map_err(storage_error)?;
        if actual.len() != expected.len()
            || actual
                .iter()
                .any(|row| expected.get(&row.key) != Some(&row.value))
        {
            return Err(integrity(
                "suppression authority rows differ from its accepted chain",
            ));
        }
        Ok(())
    }
}

fn head_key(workspace: &str) -> Vec<u8> {
    format!("head/{workspace}").into_bytes()
}
fn event_key(workspace: &str, epoch: u64) -> Vec<u8> {
    format!("event/{workspace}/{epoch:020}").into_bytes()
}
fn denied_key(workspace: &str, id: ObservationId) -> Vec<u8> {
    format!("deny/{workspace}/{id}").into_bytes()
}
