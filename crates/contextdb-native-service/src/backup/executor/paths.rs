use super::*;

impl NativeArchiveCleanup<'_> {
    pub(super) fn worker_path(
        &self,
        original: &NativeBackupRegistration,
        generation: Option<uuid::Uuid>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<PathBuf> {
        budget.check().map_err(crate::raw_index::budget_error)?;
        let root = prospective_root(&self.root)?;
        self.require_separate(&root)?;
        std::fs::create_dir_all(&root)
            .map_err(|_| integrity("archive worker root cannot be created"))?;
        let root = root
            .canonicalize()
            .map_err(|_| integrity("archive worker root is unavailable"))?;
        self.require_separate(&root)?;
        let authority = root.join(original.authority_id.to_string());
        self.require_worker_path(&authority)?;
        std::fs::create_dir_all(&authority)
            .map_err(|_| integrity("archive worker namespace cannot be created"))?;
        budget.check().map_err(crate::raw_index::budget_error)?;
        // Generations are siblings: later disposal of a sealed directory must not
        // contain its successor. The identity comes from retained job authority.
        let name = generation.map_or_else(
            || original.archive_digest.clone(),
            |instance| format!("{}.{instance}", original.archive_digest),
        );
        let path = authority.join(name);
        self.require_worker_path(&path)?;
        Ok(path)
    }

    pub(super) fn require_worker_path(&self, path: &Path) -> ServiceResult<()> {
        self.require_separate(path)?;
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                if !meta.is_dir()
                    || meta.file_type().is_symlink()
                    || path
                        .canonicalize()
                        .map_err(|_| integrity("archive worker path is unavailable"))?
                        != path
                {
                    return Err(integrity(
                        "archive worker path is not a distinct native directory",
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(integrity("archive worker path cannot be inspected")),
        }
        Ok(())
    }

    fn require_separate(&self, root: &Path) -> ServiceResult<()> {
        let keys = self
            .owner
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?;
        let ledger = self
            .owner
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("archive suppression absent"))?;
        for protected in [&self.owner.path, &keys.path, &ledger.path] {
            if root.starts_with(protected) || protected.starts_with(root) {
                return Err(crate::invalid(
                    "archive workers require a separate directory tree from primary and retained authorities",
                ));
            }
        }
        Ok(())
    }
}

fn prospective_root(path: &Path) -> ServiceResult<PathBuf> {
    let mut ancestor = path;
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(ancestor) {
            Ok(_) => {
                let mut root = ancestor
                    .canonicalize()
                    .map_err(|_| integrity("archive root ancestor is unavailable"))?;
                for name in missing.iter().rev() {
                    root.push(name);
                }
                return Ok(root);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(
                    ancestor
                        .file_name()
                        .ok_or_else(|| crate::invalid("archive root has no existing ancestor"))?
                        .to_os_string(),
                );
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| crate::invalid("archive root has no parent"))?;
            }
            Err(_) => return Err(integrity("archive root ancestor cannot be inspected")),
        }
    }
}
