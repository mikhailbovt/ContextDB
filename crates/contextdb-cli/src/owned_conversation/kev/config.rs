//! Immutable operator opt-in. Hashes bind code and weights, never source rights.

use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{FORMAT, PROFILE, PROJECTION, error};
use crate::CliResult;

pub(super) const MAX_META: usize = 16 * 1024;
pub(super) const MAX_INPUT: usize = 2 * 1024 * 1024;
pub(super) const MAX_FRAME: usize = 2 + MAX_META + MAX_INPUT;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourcePins {
    #[serde(rename = "corpus.py")]
    corpus: String,
    #[serde(rename = "trainer.py")]
    trainer: String,
    #[serde(rename = "check.py")]
    check: String,
    #[serde(rename = "conditional.py")]
    conditional: String,
}

impl SourcePins {
    fn files(&self) -> [(&str, &str); 4] {
        [
            ("corpus.py", &self.corpus),
            ("trainer.py", &self.trainer),
            ("check.py", &self.check),
            ("conditional.py", &self.conditional),
        ]
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Limits {
    pub startup_timeout_micros: u64,
    pub per_call_timeout_micros: u64,
    pub aggregate_timeout_micros: u64,
    pub inference_work: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KevConfig {
    pub(super) program: PathBuf,
    pub(super) args: Vec<String>,
    pub(super) executable_sha256: String,
    pub(super) worker: PathBuf,
    pub(super) worker_sha256: String,
    pub(super) corpus: PathBuf,
    pub(super) model_lock: PathBuf,
    pub(super) model_lock_sha256: String,
    pub(super) output_root: PathBuf,
    pub(super) run_name: String,
    pub(super) bundle_sha256: String,
    pub(super) model_profile_sha256: String,
    pub(super) tensor_sha256: String,
    pub(super) source_sha256: SourcePins,
    development_only: bool,
    model_processing: bool,
    failure_policy: FailurePolicy,
    pub(super) limits: Limits,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum FailurePolicy {
    Refuse,
}

impl std::fmt::Debug for KevConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KevConfig")
            .field("limits", &self.limits)
            .field("development_only", &self.development_only)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
pub(crate) struct PolicyBinding<'a> {
    config: &'a KevConfig,
    format: &'static str,
    profile: &'static str,
    projection: &'static str,
    feature: &'static str,
    utility: &'static str,
    max_logit: u64,
    max_metadata_bytes: usize,
    max_input_bytes: usize,
    state_tokens: u32,
    row_tokens: u32,
    state_bytes: u32,
    branch_bytes: u32,
}

impl std::fmt::Debug for PolicyBinding<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KevPolicyBinding")
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

impl KevConfig {
    pub(crate) fn validate(&self) -> CliResult<()> {
        if !self.development_only
            || !self.model_processing
            || self.args.len() != 2
            || self
                .args
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != BTreeSet::from(["-I", "-u"])
            || !valid_run_name(&self.run_name)
            || !(1..=300_000_000).contains(&self.limits.startup_timeout_micros)
            || !(1..=10_000_000).contains(&self.limits.per_call_timeout_micros)
            || !(1..=10_000_000).contains(&self.limits.aggregate_timeout_micros)
            || self.limits.per_call_timeout_micros > self.limits.aggregate_timeout_micros
            || !(1..=512).contains(&self.limits.inference_work)
        {
            return Err(error("invalid development Kev operator policy").into());
        }
        for value in [
            &self.executable_sha256,
            &self.worker_sha256,
            &self.model_lock_sha256,
            &self.bundle_sha256,
            &self.model_profile_sha256,
            &self.tensor_sha256,
        ] {
            if !digest_valid(value) {
                return Err(error("invalid Kev commitment").into());
            }
        }
        for (_, digest) in self.source_sha256.files() {
            if !digest_valid(digest) {
                return Err(error("invalid Kev source commitment").into());
            }
        }
        self.verify_files()
    }

    /// Recheck admitted code immediately before launch, after retained binding.
    pub(super) fn verify_files(&self) -> CliResult<()> {
        verify_file(&self.program, &self.executable_sha256, 64 * 1024 * 1024)?;
        verify_file(&self.worker, &self.worker_sha256, 1024 * 1024)?;
        verify_file(&self.model_lock, &self.model_lock_sha256, 64 * 1024)?;
        checked_path(&self.corpus, false)?;
        checked_path(&self.output_root, false)?;
        let bundle = self.output_root.join(&self.run_name);
        checked_path(&bundle, false)?;
        checked_path(&bundle.join("complete.json"), true)?;
        verify_file(&bundle.join("bundle.json"), &self.bundle_sha256, 64 * 1024)?;
        let parent = self
            .worker
            .parent()
            .ok_or_else(|| error("invalid worker location"))?;
        for (name, digest) in self.source_sha256.files() {
            verify_file(&parent.join(name), digest, 1024 * 1024)?;
        }
        Ok(())
    }

    pub(crate) fn binding(&self) -> PolicyBinding<'_> {
        PolicyBinding {
            config: self,
            format: FORMAT,
            profile: PROFILE,
            projection: PROJECTION,
            feature: contextdb_context::SEMANTIC_SCORING_FEATURE_SCHEMA,
            utility: "sigmoid(logit);p<=0.5:STOP;otherwise:finite_micros(2*p-1)",
            max_logit: 1_000_000,
            max_metadata_bytes: MAX_META,
            max_input_bytes: MAX_INPUT,
            state_tokens: 2048,
            row_tokens: 4096,
            state_bytes: 65536,
            branch_bytes: 65536,
        }
    }

    pub(crate) fn binding_bytes(&self) -> CliResult<Vec<u8>> {
        serde_json::to_vec(&self.binding()).map_err(|_| error("Kev policy cannot be bound").into())
    }

    pub(super) fn digest(&self) -> CliResult<String> {
        Ok(sha256(&self.binding_bytes()?))
    }
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes).as_ref())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}
fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_run_name(value: &str) -> bool {
    value.len() <= 64
        && value.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !matches!(value, "con" | "prn" | "aux" | "nul")
        && !["com", "lpt"].iter().any(|prefix| {
            value.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
            })
        })
}

fn checked_path(path: &Path, file: bool) -> CliResult<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(error("Kev path must be absolute and direct").into());
    }
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor).map_err(|_| error("Kev path unavailable"))?;
        if meta.file_type().is_symlink() {
            return Err(error("Kev symbolic path refused").into());
        }
    }
    let meta = fs::symlink_metadata(path).map_err(|_| error("Kev path unavailable"))?;
    if (file && !meta.is_file()) || (!file && !meta.is_dir()) {
        return Err(error("Kev path type differs").into());
    }
    Ok(())
}

fn verify_file(path: &Path, expected: &str, cap: u64) -> CliResult<()> {
    checked_path(path, true)?;
    let mut file = fs::File::open(path).map_err(|_| error("Kev pinned file unavailable"))?;
    let length = file
        .metadata()
        .map_err(|_| error("Kev pinned file unavailable"))?
        .len();
    if length > cap {
        return Err(error("Kev pinned file exceeds cap").into());
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| error("Kev pinned file unreadable"))?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > length {
            return Err(error("Kev pinned file changed").into());
        }
        digest.update(&buffer[..count]);
    }
    if total != length || hex(digest.finalize().as_ref()) != expected {
        return Err(error("Kev pinned file commitment differs").into());
    }
    Ok(())
}
