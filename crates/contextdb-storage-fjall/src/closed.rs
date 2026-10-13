//! Exclusive closed-directory admission for the pinned Fjall 3 format.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use super::{Result, backend};

// These are the on-disk lock and version names of the pinned Fjall dependency.
const LOCK: &str = "lock";
const VERSION: &str = "version";

/// Holds the same OS file lock as Fjall, after all backend owners and their
/// snapshots have released it. No file is created, renamed or deleted. Callers
/// must separately verify native identity, authorization and managed path custody.
#[derive(Debug)]
pub struct ClosedFjallDirectory {
    _lock: File,
    path: PathBuf,
}

impl ClosedFjallDirectory {
    /// Acquire an existing directory's backend lock without opening its data.
    /// None means it is still held. The lock must remain alive across the caller's
    /// controlled operation; an earlier successful probe is not current authority.
    pub fn try_acquire(path: &Path) -> Result<Option<Self>> {
        require_directory(path)?;
        let lock_path = path.join(LOCK);
        require_file(&lock_path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(backend)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self {
                _lock: file,
                path: path.to_path_buf(),
            })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(error) => Err(backend(error)),
        }
    }

    /// Directory whose existing lock was acquired; this is a locator, not a
    /// durable native-instance or deletion receipt.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub(super) fn require_existing(path: &Path) -> Result<()> {
    require_directory(path)?;
    require_file(&path.join(VERSION))?;
    require_file(&path.join(LOCK))
}

fn require_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(backend)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(backend("existing database path is not a directory"));
    }
    Ok(())
}

fn require_file(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(backend)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(backend("existing database control is not a regular file"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FjallStorage;
    use contextdb_storage::{
        Durability, Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine, WriteTransaction,
    };

    #[test]
    fn closed_directory_lock_waits_for_storage_and_all_snapshot_clones() {
        let root = tempfile::tempdir().expect("root");
        let db = FjallStorage::open(root.path()).expect("open");
        let space = Keyspace::new("payload").expect("space");
        let mut tx = db.begin_write().expect("tx");
        tx.put(&space, b"key".to_vec(), b"preserved".to_vec())
            .expect("put");
        tx.commit(Durability::Sync).expect("commit");
        let snapshot = db.begin_read(SnapshotSelector::Latest).expect("snapshot");
        let clone = snapshot.clone();
        assert!(
            ClosedFjallDirectory::try_acquire(root.path())
                .expect("busy")
                .is_none()
        );
        drop(db);
        assert!(
            FjallStorage::try_open_existing(root.path())
                .expect("snapshot holds backend")
                .is_none()
        );
        drop(snapshot);
        assert!(
            ClosedFjallDirectory::try_acquire(root.path())
                .expect("clone holds backend")
                .is_none()
        );
        assert_eq!(
            clone.get(&space, b"key").expect("old view"),
            Some(b"preserved".to_vec())
        );
        drop(clone);
        let guard = ClosedFjallDirectory::try_acquire(root.path())
            .expect("lock")
            .expect("drained");
        assert!(
            FjallStorage::try_open_existing(root.path())
                .expect("guard excludes reopen")
                .is_none()
        );
        drop(guard);
        let db = FjallStorage::try_open_existing(root.path())
            .expect("reopen")
            .expect("released");
        assert_eq!(
            db.begin_read(SnapshotSelector::Latest)
                .expect("view")
                .get(&space, b"key")
                .expect("unchanged"),
            Some(b"preserved".to_vec())
        );
    }

    #[test]
    fn closed_directory_admission_never_creates_missing_controls() {
        let root = tempfile::tempdir().expect("root");
        let missing = root.path().join("absent");
        assert!(FjallStorage::try_open_existing(&missing).is_err());
        assert!(FjallStorage::check_existing_controls(&missing).is_err());
        assert!(ClosedFjallDirectory::try_acquire(&missing).is_err());
        assert!(!missing.exists());
        assert!(FjallStorage::try_open_existing(root.path()).is_err());
        assert!(FjallStorage::check_existing_controls(root.path()).is_err());
        assert!(ClosedFjallDirectory::try_acquire(root.path()).is_err());
        assert_eq!(
            std::fs::read_dir(root.path())
                .expect("unchanged empty directory")
                .count(),
            0
        );
    }

    #[test]
    fn existing_control_check_admits_busy_owner_without_opening_or_repairing() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("database");
        let db = FjallStorage::open(&path).expect("live owner");
        let space = Keyspace::new("payload").expect("space");
        let mut transaction = db.begin_write().expect("write");
        transaction
            .put(&space, b"key".to_vec(), b"retained".to_vec())
            .expect("put");
        transaction.commit(Durability::Sync).expect("commit");
        let names = db.physical_keyspace_names();
        let sequence = db
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot")
            .sequence();
        FjallStorage::check_existing_controls(&path).expect("busy controls");
        assert!(
            FjallStorage::try_open_existing(&path)
                .expect("busy database")
                .is_none()
        );
        assert_eq!(db.physical_keyspace_names(), names);
        assert_eq!(
            db.begin_read(SnapshotSelector::Latest)
                .expect("unchanged snapshot")
                .sequence(),
            sequence
        );
        drop(db);
        for control in [VERSION, LOCK] {
            let retained = root.path().join(format!("retained-{control}"));
            std::fs::rename(path.join(control), &retained).expect("hold fixture control");
            assert!(FjallStorage::check_existing_controls(&path).is_err());
            assert!(!path.join(control).exists());
            std::fs::rename(retained, path.join(control)).expect("restore fixture control");
        }
        FjallStorage::check_existing_controls(&path).expect("retained controls");
        let db = FjallStorage::try_open_existing(&path)
            .expect("reopen")
            .expect("closed");
        assert_eq!(db.physical_keyspace_names(), names);
        assert_eq!(
            db.begin_read(SnapshotSelector::Latest)
                .expect("retained read")
                .get(&space, b"key")
                .expect("retained value"),
            Some(b"retained".to_vec())
        );
        assert_eq!(
            db.begin_read(SnapshotSelector::Latest)
                .expect("reopened snapshot")
                .sequence(),
            sequence
        );
    }
}
