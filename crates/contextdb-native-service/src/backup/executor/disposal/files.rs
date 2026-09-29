use super::*;

pub(super) fn exists(path: &Path) -> ServiceResult<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(integrity("worker disposal path cannot be inspected")),
    }
}

pub(super) fn quarantine_path(
    path: &Path,
    disposal: &NativeBackupWorkerDisposal,
) -> ServiceResult<PathBuf> {
    // Stable across intent/finish receipts and cold restart; both names stay in
    // the managed authority namespace, never inside a replacement generation.
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| integrity("worker directory name is invalid"))?;
    Ok(path.with_file_name(format!(".{name}.dispose.{}", disposal.binding.seal.digest)))
}

pub(super) fn remove_portion(
    root: &Path,
    closed: Option<ClosedFjallDirectory>,
    maximum: u32,
    budget: &mut QueryBudget,
) -> ServiceResult<u32> {
    let mut removed = 0;
    while removed < maximum {
        budget.check().map_err(crate::raw_index::budget_error)?;
        let Some((path, directory)) = next_entry(root, budget)? else {
            break;
        };
        if closed.is_none() {
            return Err(integrity(
                "worker files require their backend exclusion lock",
            ));
        }
        if directory {
            std::fs::remove_dir(&path)
        } else {
            std::fs::remove_file(&path)
        }
        .map_err(|_| integrity("worker disposal could not unlink an entry"))?;
        removed += 1;
    }
    if next_entry(root, budget)?.is_none() && removed < maximum {
        let lock = root.join("lock");
        if exists(&lock)? && closed.is_none() {
            return Err(integrity("worker lock cannot be removed without exclusion"));
        }
        // Data is gone. Windows requires releasing the OS handle before the
        // last empty-directory controls are removed; custody remains fenced.
        drop(closed);
        if exists(&lock)? {
            std::fs::remove_file(&lock)
                .map_err(|_| integrity("worker lock could not be unlinked"))?;
            removed += 1;
        }
        // Windows can defer unlink until the lock handle closes. No cooperating
        // native open can cross the caller's retained seal/publication fence.
        if removed < maximum {
            std::fs::remove_dir(root)
                .map_err(|_| integrity("empty worker quarantine could not be removed"))?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn next_entry(root: &Path, budget: &mut QueryBudget) -> ServiceResult<Option<(PathBuf, bool)>> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.last() {
        budget.check().map_err(crate::raw_index::budget_error)?;
        if stack.len() > 64 {
            return Err(exhausted("worker directory exceeds 64 levels"));
        }
        let mut found = None;
        for entry in std::fs::read_dir(directory)
            .map_err(|_| integrity("worker directory cannot be read"))?
        {
            let entry = entry.map_err(|_| integrity("worker directory entry cannot be read"))?;
            budget
                .charge(1, 512)
                .map_err(crate::raw_index::budget_error)?;
            if directory == root && entry.file_name() == "lock" {
                continue;
            }
            found = Some(entry.path());
            break;
        }
        let Some(path) = found else {
            if directory == root {
                return Ok(None);
            }
            return Ok(Some((directory.clone(), true)));
        };
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| integrity("worker entry cannot be inspected"))?;
        if metadata.file_type().is_symlink()
            || path
                .canonicalize()
                .map_err(|_| integrity("worker entry cannot be resolved"))?
                != path
        {
            return Err(integrity(
                "worker disposal refuses an aliased filesystem entry",
            ));
        }
        if metadata.is_file() {
            return Ok(Some((path, false)));
        }
        if !metadata.is_dir() {
            return Err(integrity(
                "worker disposal refuses a special filesystem entry",
            ));
        }
        stack.push(path);
    }
    Ok(None)
}
