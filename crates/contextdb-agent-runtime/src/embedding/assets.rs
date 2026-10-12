use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, PathBuf},
};

use contextdb_recall::QueryBudget;
use contextdb_service::{ServiceResult, TextEmbeddingProfile};
use sha2::{Digest, Sha256};

use super::{LocalEmbeddingConfig, charge, invalid, unavailable};

pub(super) fn validate_manifest(artifacts: &BTreeMap<String, String>) -> ServiceResult<()> {
    if artifacts.is_empty() || artifacts.len() > 128 {
        return Err(invalid("embedding artifact count refused"));
    }
    for (name, sha) in artifacts {
        let mut parts = std::path::Path::new(name).components();
        if name.len() > 256
            || !matches!(parts.next(), Some(Component::Normal(_)))
            || parts.next().is_some()
            || name.contains(['/', '\\', ':'])
            || sha.len() != 64
            || !sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("embedding artifact manifest refused"));
        }
    }
    Ok(())
}

pub(super) fn verify(
    config: &LocalEmbeddingConfig,
    profile: &TextEmbeddingProfile,
    budget: &mut QueryBudget,
) -> ServiceResult<(PathBuf, PathBuf)> {
    if !config.program.is_absolute() || !config.model.is_absolute() {
        return Err(invalid("embedding asset paths must be absolute"));
    }
    validate_manifest(&config.runtime_artifacts)?;
    charge(budget, 4, 4096)?;
    let program = config
        .program
        .canonicalize()
        .map_err(|_| unavailable("embedding program absent"))?;
    let model = config
        .model
        .canonicalize()
        .map_err(|_| unavailable("embedding weights absent"))?;
    let directory = program
        .parent()
        .ok_or_else(|| invalid("embedding program directory absent"))?;
    let program_name = program
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| invalid("embedding program name refused"))?;
    if !config.runtime_artifacts.contains_key(program_name) {
        return Err(invalid("embedding executable is not pinned"));
    }
    let mut observed = BTreeSet::new();
    charge(budget, 1, 65536)?;
    for entry in fs::read_dir(directory)
        .map_err(|_| unavailable("embedding runtime directory unavailable"))?
    {
        charge(budget, 1, 512)?;
        let entry =
            entry.map_err(|_| unavailable("embedding artifact directory entry unavailable"))?;
        let kind = entry
            .file_type()
            .map_err(|_| unavailable("embedding artifact type unavailable"))?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| invalid("embedding artifact name refused"))?
            .to_owned();
        let lower = name.to_ascii_lowercase();
        let executable = name == program_name
            || lower.ends_with(".dll")
            || lower.ends_with(".so")
            || lower.contains(".so.")
            || lower.ends_with(".dylib");
        if executable {
            if !kind.is_file() || !config.runtime_artifacts.contains_key(&name) {
                return Err(invalid(
                    "embedding runtime has unpinned executable artifacts",
                ));
            }
            observed.insert(name);
        }
    }
    if observed != config.runtime_artifacts.keys().cloned().collect() {
        return Err(invalid("embedding runtime artifact set differs"));
    }
    for (name, expected) in &config.runtime_artifacts {
        verify_file(&directory.join(name), expected, budget)?;
    }
    verify_file(&model, &profile.weights_sha256, budget)?;
    Ok((program, model))
}

fn verify_file(
    path: &std::path::Path,
    expected: &str,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    charge(budget, 2, 65536 + 1024)?;
    let mut file =
        fs::File::open(path).map_err(|_| unavailable("embedding artifact read failed"))?;
    let length = file
        .metadata()
        .map_err(|_| unavailable("embedding artifact metadata failed"))?
        .len();
    if length > 16 * 1024 * 1024 * 1024 {
        return Err(invalid("embedding artifact length refused"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65536];
    let mut total = 0_u64;
    loop {
        // Charge before every physical read, including the final EOF observation.
        charge(budget, 1, buffer.len() as u64)?;
        let read = file
            .read(&mut buffer)
            .map_err(|_| unavailable("embedding artifact read failed"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| invalid("embedding artifact byte count overflow"))?;
        if total > length {
            return Err(invalid("embedding artifact grew during verification"));
        }
        hasher.update(&buffer[..read]);
    }
    let actual: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if total != length || actual != expected {
        return Err(invalid("embedding artifact SHA256 mismatch"));
    }
    Ok(())
}
