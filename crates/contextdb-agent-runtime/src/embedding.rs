//! Pinned local encoder with one owned backend process and no transport retries.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Mutex, MutexGuard},
    thread,
    time::Duration,
};

use contextdb_core::ContentDigest;
use contextdb_recall::QueryBudget;
use contextdb_service::{
    EmbeddedText, EmbeddingTextKind, ErrorCode, ServiceError, ServiceResult, TextEmbeddingAdapter,
    TextEmbeddingProfile,
};
use serde::{Deserialize, Serialize};

use super::{charge, exhausted, invalid};

mod assets;
mod http;
#[cfg(test)]
mod tests;

/// Trusted host paths and pinned artifact manifest, never model-supplied config.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEmbeddingConfig {
    /// Absolute path to the pinned server executable.
    pub program: PathBuf,
    /// Absolute path to the pinned embedding GGUF.
    pub model: PathBuf,
    /// Complete sorted executable/dynamic-library name to lowercase SHA256 map.
    /// Names are single path components relative to the executable directory.
    pub runtime_artifacts: BTreeMap<String, String>,
    /// Dedicated loopback port. An occupied port is refused before launch.
    pub port: u16,
}

/// BLAKE3 identity of the complete sorted backend artifact name/SHA256 manifest.
pub fn embedding_backend_artifacts_digest(
    artifacts: &BTreeMap<String, String>,
) -> ServiceResult<ContentDigest> {
    assets::validate_manifest(artifacts)?;
    let bytes = serde_json::to_vec(artifacts)
        .map_err(|_| invalid("embedding artifact manifest encoding failed"))?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"contextdb.embedding-backend-artifacts.v1\0");
    hash.update(&bytes);
    Ok(ContentDigest::from_bytes(*hash.finalize().as_bytes()))
}

#[derive(Debug)]
struct Backend {
    child: Option<Child>,
}
impl Backend {
    fn terminate(&mut self, budget: &mut QueryBudget) -> ServiceResult<()> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        child
            .kill()
            .map_err(|_| unavailable("embedding process termination failed"))?;
        loop {
            if child
                .try_wait()
                .map_err(|_| unavailable("embedding process cleanup failed"))?
                .is_some()
            {
                self.child.take();
                return Ok(());
            }
            charge(budget, 1, 0)?;
            let delay = budget
                .remaining_timeout_micros()
                .map_err(|_| exhausted("embedding process cleanup allowance exhausted"))?
                .min(1000);
            thread::sleep(Duration::from_micros(delay));
        }
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            if !matches!(child.try_wait(), Ok(Some(_))) {
                // Reap outside an already exhausted request. This child is never
                // reused/restarted; a cleanup thread cannot perform inference.
                let _ = thread::Builder::new()
                    .name("contextdb-embedding-reap".into())
                    .spawn(move || {
                        let _ = child.wait();
                    });
            }
        }
    }
}

/// Local Qwen encoder. Launch verifies exact GGUF and all runtime artifacts;
/// tokenization and each single-input inference use one caller-owned budget.
/// This component does not enable native retrieval or grant processing rights.
pub struct OwnedLocalEmbedding {
    profile: TextEmbeddingProfile,
    model_path: String,
    port: u16,
    backend: Mutex<Option<Backend>>,
}
impl std::fmt::Debug for OwnedLocalEmbedding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedLocalEmbedding")
            .field("profile", &self.profile)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl OwnedLocalEmbedding {
    /// Verify provisioned assets and launch a dedicated backend. Startup uses
    /// this budget; per-request budgets do not pay provisioning repeatedly.
    /// On failure, the exact child is terminated; OS reaping may finish on its
    /// cleanup thread after the allowance expires. No fallback or restart.
    pub fn launch(config: &LocalEmbeddingConfig, budget: &mut QueryBudget) -> ServiceResult<Self> {
        if config.port == 0 {
            return Err(invalid("embedding port is invalid"));
        }
        let profile = TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(
            embedding_backend_artifacts_digest(&config.runtime_artifacts)?,
        );
        let (program, model) = assets::verify(config, &profile, budget).map_err(|error| {
            if error.code == ErrorCode::BudgetExhausted {
                exhausted("embedding asset verification allowance exhausted")
            } else {
                error
            }
        })?;
        let model_path = model
            .to_str()
            .ok_or_else(|| invalid("embedding model path is not UTF-8"))?
            .to_owned();
        // Reserve the configured address while constructing the command. Release
        // only immediately before spawn; readiness also checks the owned child.
        let probe = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, config.port))
            .map_err(|_| unavailable("embedding port is occupied"))?;
        charge(budget, 1, 0)?;
        let mut command = Command::new(program);
        command
            .args(["-m"])
            .arg(&model)
            .args([
                "--embedding",
                "--pooling",
                "last",
                "--embd-normalize",
                "2",
                "-c",
                "4096",
                "-b",
                "4096",
                "-ub",
                "4096",
                "-ngl",
                "99",
                "-np",
                "1",
                "--host",
                "127.0.0.1",
                "--port",
            ])
            .arg(config.port.to_string())
            .args([
                "--no-webui",
                "--cache-ram",
                "0",
                "--threads",
                "8",
                "--no-context-shift",
                "--alias",
                "contextdb-qwen3-06b-q8",
                "--offline",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_clear();
        // GPU driver compilation caches use these OS directory paths. Preserve
        // them while excluding arbitrary model/provider configuration variables.
        for key in [
            "SystemRoot",
            "WINDIR",
            "PATH",
            "TEMP",
            "TMP",
            "CUDA_PATH",
            "LOCALAPPDATA",
            "APPDATA",
            "USERPROFILE",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command.current_dir(
            config
                .program
                .parent()
                .ok_or_else(|| invalid("embedding program directory missing"))?,
        );
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        drop(probe);
        let child = command
            .spawn()
            .map_err(|_| unavailable("embedding backend launch failed"))?;
        let adapter = Self {
            profile,
            model_path,
            port: config.port,
            backend: Mutex::new(Some(Backend { child: Some(child) })),
        };
        let mut backend = adapter.lock(budget)?;
        loop {
            adapter.check_live(&mut backend, budget).map_err(|error| {
                if error.code == ErrorCode::BudgetExhausted {
                    exhausted("embedding startup allowance exhausted")
                } else {
                    error
                }
            })?;
            match adapter.props(budget) {
                Ok(()) => break,
                Err(error) if error.code == ErrorCode::ProviderUnavailable => {
                    charge(budget, 1, 0)?;
                    let delay = budget
                        .remaining_timeout_micros()
                        .map_err(|_| exhausted("embedding startup allowance exhausted"))?
                        .min(5000);
                    thread::sleep(Duration::from_micros(delay));
                }
                Err(error) => return Err(error),
            }
        }
        drop(backend);
        Ok(adapter)
    }

    fn lock<'a>(
        &'a self,
        budget: &mut QueryBudget,
    ) -> ServiceResult<MutexGuard<'a, Option<Backend>>> {
        loop {
            budget
                .check()
                .map_err(|_| exhausted("embedding allowance exhausted"))?;
            match self.backend.try_lock() {
                Ok(guard) => return Ok(guard),
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(unavailable("embedding backend lock failed"));
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    charge(budget, 1, 0)?;
                    let delay = budget
                        .remaining_timeout_micros()
                        .map_err(|_| exhausted("embedding allowance exhausted"))?
                        .min(1000);
                    thread::sleep(Duration::from_micros(delay));
                }
            }
        }
    }

    fn check_live(&self, backend: &mut Option<Backend>, budget: &QueryBudget) -> ServiceResult<()> {
        budget
            .check()
            .map_err(|_| exhausted("embedding allowance exhausted"))?;
        let process = backend
            .as_mut()
            .ok_or_else(|| unavailable("embedding backend closed"))?;
        if process
            .child
            .as_mut()
            .ok_or_else(|| unavailable("embedding backend child absent"))?
            .try_wait()
            .map_err(|_| unavailable("embedding process state failed"))?
            .is_some()
        {
            backend.take();
            return Err(unavailable("embedding backend exited"));
        }
        Ok(())
    }

    /// Stop and reap the exact child within a separate supplied allowance. Drop
    /// also terminates it, but may finish OS reaping on a dedicated cleanup thread
    /// when the request has no remaining time. No cleanup is a restart or retry.
    pub fn shutdown(&mut self, budget: &mut QueryBudget) -> ServiceResult<()> {
        charge(budget, 1, 0)?;
        let backend = self
            .backend
            .get_mut()
            .map_err(|_| unavailable("embedding backend lock failed"))?;
        if let Some(mut process) = backend.take() {
            process.terminate(budget)?;
        }
        Ok(())
    }

    fn props(&self, budget: &mut QueryBudget) -> ServiceResult<()> {
        let bytes = http::request(self.port, "GET", "/props", &[], 128 * 1024, budget)?;
        charge(budget, 1, (bytes.len() * 32) as u64)?;
        let props: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("embedding properties are malformed"))?;
        let build = props
            .get("build_info")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if !build.starts_with("b10964-")
            || !build.contains("b29c606e")
            || props.get("model_path").and_then(serde_json::Value::as_str)
                != Some(self.model_path.as_str())
            || props.get("total_slots").and_then(serde_json::Value::as_u64) != Some(1)
            || props
                .pointer("/default_generation_settings/n_ctx")
                .and_then(serde_json::Value::as_u64)
                != Some(4096)
        {
            return Err(invalid(
                "embedding backend properties differ from pinned launch",
            ));
        }
        Ok(())
    }

    fn encode(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        backend: &mut Option<Backend>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        if text.is_empty() || text.len() > self.profile.max_text_bytes as usize {
            return Err(invalid("embedding text length refused"));
        }
        charge(
            budget,
            1,
            (text.len() + self.profile.query_instruction.len() + 20) as u64,
        )?;
        let input = self.profile.input_text(kind, text)?;
        self.check_live(backend, budget)?;
        self.props(budget)?;
        let tokenize = TokenizeRequest {
            content: &input,
            add_special: true,
            parse_special: false,
            with_pieces: false,
        };
        let tokens: Tokenized = self.post("/tokenize", &tokenize, 128 * 1024, budget)?;
        if tokens.tokens.is_empty()
            || tokens.tokens.len() > self.profile.max_input_tokens as usize
            || tokens.tokens.iter().any(|t| *t < 0)
        {
            return Err(invalid(
                "embedding token sequence refused; input was not truncated",
            ));
        }
        let mut token_hash = blake3::Hasher::new();
        for token in &tokens.tokens {
            charge(budget, 1, 4)?;
            token_hash.update(&token.to_le_bytes());
        }
        // Exact token-array branch in the pinned backend adds no further specials.
        // The request's model string is routing data, not loaded-weight evidence.
        self.check_live(backend, budget)?;
        let inference = EmbeddingRequest {
            model: "contextdb-qwen3-06b-q8",
            input: &tokens.tokens,
            encoding_format: "float",
            embd_normalize: 2,
        };
        let output: Embeddings = self.post("/v1/embeddings", &inference, 128 * 1024, budget)?;
        self.check_live(backend, budget)?;
        if output.object != "list"
            || output.data.len() != 1
            || output.data[0].index != 0
            || output.data[0].object != "embedding"
            || output.model != "contextdb-qwen3-06b-q8"
            || output.usage.prompt_tokens != tokens.tokens.len() as u32
            || output.usage.total_tokens != output.usage.prompt_tokens
        {
            return Err(invalid("embedding response or token accounting mismatch"));
        }
        let values = output
            .data
            .into_iter()
            .next()
            .ok_or_else(|| invalid("embedding result absent"))?
            .embedding;
        let mut vector_hash = blake3::Hasher::new();
        for value in &values {
            charge(budget, 1, 4)?;
            vector_hash.update(&value.to_le_bytes());
        }
        let result = EmbeddedText {
            profile_digest: self.profile.digest()?,
            kind,
            text_digest: digest(text.as_bytes()),
            input_digest: digest(input.as_bytes()),
            tokens_digest: ContentDigest::from_bytes(*token_hash.finalize().as_bytes()),
            token_count: tokens.tokens.len() as u32,
            values,
            vector_digest: ContentDigest::from_bytes(*vector_hash.finalize().as_bytes()),
        };
        result.validate(&self.profile, kind, text, budget)?;
        Ok(result)
    }

    fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &'static str,
        value: &impl Serialize,
        cap: usize,
        budget: &mut QueryBudget,
    ) -> ServiceResult<T> {
        // serde's output and value trees are bounded by text/token input caps;
        // pay a conservative allocation envelope before constructing the wire.
        charge(budget, 1, 128 * 1024)?;
        let wire =
            serde_json::to_vec(value).map_err(|_| invalid("embedding request encoding failed"))?;
        let bytes = http::request(self.port, "POST", path, &wire, cap, budget)?;
        charge(budget, 1, (bytes.len() * 4) as u64)?;
        serde_json::from_slice(&bytes).map_err(|_| invalid("embedding response is malformed"))
    }
}

impl TextEmbeddingAdapter for OwnedLocalEmbedding {
    fn profile(&self) -> &TextEmbeddingProfile {
        &self.profile
    }
    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        let mut backend = self.lock(budget)?;
        let result = self.encode(kind, text, &mut backend, budget);
        // An interrupted/invalid response closes the owned encoder. A later call
        // cannot silently reuse an uncertain slot or change the backend profile.
        if result.is_err() {
            backend.take();
        }
        result
    }
}

#[derive(Serialize)]
struct TokenizeRequest<'a> {
    content: &'a str,
    add_special: bool,
    parse_special: bool,
    with_pieces: bool,
}
#[derive(Serialize)]
struct EmbeddingRequest<'a> {
    model: &'a str,
    input: &'a [i32],
    encoding_format: &'a str,
    embd_normalize: i32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tokenized {
    tokens: Vec<i32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Embeddings {
    object: String,
    model: String,
    data: Vec<EmbeddingRow>,
    usage: EmbeddingUsage,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingRow {
    object: String,
    index: u32,
    embedding: Vec<f32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingUsage {
    prompt_tokens: u32,
    total_tokens: u32,
}

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}
fn unavailable(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::ProviderUnavailable, message, false)
}
