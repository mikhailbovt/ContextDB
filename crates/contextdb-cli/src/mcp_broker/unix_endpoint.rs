//! Cross-process ownership covers socket creation, listener lifetime and cleanup.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

#[derive(Debug)]
pub(super) struct EndpointOwner {
    _lock: File,
}

impl EndpointOwner {
    pub(super) fn claim(socket_name: &str) -> io::Result<Self> {
        let path = Path::new(socket_name).with_extension("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)?;
        let metadata = lock.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "MCP broker ownership lock must be an owner-only, singly linked regular file",
            ));
        }
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "another MCP broker owns the Unix endpoint",
                ));
            }
            Err(TryLockError::Error(error)) => return Err(error),
        }
        let current = fs::symlink_metadata(&path)?;
        if !current.is_file()
            || current.dev() != metadata.dev()
            || current.ino() != metadata.ino()
            || current.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "MCP broker ownership lock changed identity during acquisition",
            ));
        }
        // Keep the lock inode after release: unlinking could give simultaneous
        // owners locks on different inodes at the same path.
        Ok(Self { _lock: lock })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn ownership_is_exclusive_before_bind_and_reuses_the_same_inode() {
        let directory = tempfile::tempdir().expect("fixture");
        let socket = directory.path().join("broker.sock");
        let socket_name = socket.to_str().expect("socket path");
        let first = EndpointOwner::claim(socket_name).expect("first owner");
        let lock_path = socket.with_extension("lock");
        let metadata = fs::symlink_metadata(&lock_path).expect("lock metadata");
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(
            EndpointOwner::claim(socket_name)
                .expect_err("competing owner")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let other_socket = directory.path().join("independent.sock");
        EndpointOwner::claim(other_socket.to_str().expect("independent path"))
            .expect("independent endpoints do not block");
        drop(first);
        let _next = EndpointOwner::claim(socket_name).expect("next owner");
        assert_eq!(
            fs::symlink_metadata(lock_path).expect("same lock").ino(),
            metadata.ino()
        );
    }

    #[test]
    fn ownership_rejects_symlinks_hard_links_and_shared_files() {
        for kind in ["symlink", "hard-link", "shared"] {
            let directory = tempfile::tempdir().expect("fixture");
            let socket = directory.path().join("broker.sock");
            let lock_path = socket.with_extension("lock");
            let target = directory.path().join("unrelated");
            fs::write(&target, b"must remain unchanged").expect("unrelated file");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
            match kind {
                "symlink" => symlink(&target, &lock_path).expect("symlink"),
                "hard-link" => fs::hard_link(&target, &lock_path).expect("hard link"),
                _ => {
                    fs::write(&lock_path, b"shared").expect("shared lock");
                    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644))
                        .expect("shared mode");
                }
            }
            assert!(EndpointOwner::claim(socket.to_str().expect("socket path")).is_err());
            assert_eq!(
                fs::read(&target).expect("unrelated bytes"),
                b"must remain unchanged"
            );
        }
    }
}
