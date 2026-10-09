use super::*;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Component,
};

pub(super) fn validate_root(root: &Path, must_exist: bool) -> Result<()> {
    if !root.is_absolute()
        || root
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid());
    }
    for ancestor in root.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if linked(&metadata) || !metadata.is_dir() {
                    return Err(invalid());
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && ancestor == root
                    && !must_exist => {}
            Err(_) => return Err(invalid()),
        }
    }
    Ok(())
}
fn linked(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}
pub(super) fn regular(path: &Path) -> Result<bool> {
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid())?;
    Ok(metadata.is_file() && !linked(&metadata))
}
pub(super) fn read_bounded(path: &Path, limit: usize, budget: &mut QueryBudget) -> Result<Vec<u8>> {
    if !regular(path)? {
        return Err(invalid());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid())?;
    if metadata.len() > limit as u64 {
        return Err(invalid());
    }
    charge(budget, 1, metadata.len())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|_| invalid())?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() > limit || bytes.len() as u64 != metadata.len() {
        return Err(invalid());
    }
    Ok(bytes)
}
pub(super) fn write_new(
    root: &Path,
    name: &str,
    bytes: &[u8],
    budget: &mut QueryBudget,
) -> Result<()> {
    validate_root(root, true)?;
    charge(budget, 1, bytes.len() as u64)?;
    let pending = root.join(format!("{name}.part"));
    let final_path = root.join(name);
    if final_path.try_exists().map_err(|_| invalid())? {
        return Err(invalid());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .map_err(|_| invalid())?;
    file.write_all(bytes).map_err(|_| invalid())?;
    file.sync_all().map_err(|_| invalid())?;
    drop(file);
    fs::rename(&pending, &final_path).map_err(|_| invalid())?;
    Ok(())
}
