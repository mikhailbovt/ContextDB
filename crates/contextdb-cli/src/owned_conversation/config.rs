//! Trusted operator configuration, independent of the conversation protocol.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use contextdb_agent_runtime::{
    LocalEmbeddingConfig, RollingPolicy, RuntimeSettings, embedding_backend_artifacts_digest,
};
use contextdb_context::{
    BlockId, ContextBudgets, OutgoingBudget, OutgoingMessage, OutgoingRole, OutgoingZone,
    PackPurpose,
};
use contextdb_continuity::OwnedRunIdentity;
use contextdb_core::{
    ActorId, AgentId, AgentRunId, ContentDigest, MAX_ROUTER_TRACE_BYTES,
    MAX_ROUTER_TRACE_PAGE_BYTES, MAX_ROUTER_TRACE_PAGES, MemorySubjectId, RawFilter, ScopeId,
    SessionId, WorkspaceId,
};
use contextdb_service::{OwnedHybridLimits, RouterTraceProfile, TextEmbeddingProfile};
use serde::{Deserialize, Serialize};

use super::invalid;
use super::kev::{KevConfig, PolicyBinding};
use super::preparation;
use super::reader::LocalReaderConfig;
use crate::CliResult;

const MAX_CONFIG_BYTES: u64 = 128 * 1024;

#[cfg(test)]
mod tests;

/// Fixed native trace profile; conversation frames cannot override these bounds.
#[derive(Serialize)]
struct TraceSettingsBinding {
    profile: RouterTraceProfile,
    version: u16,
    max_trace_bytes: usize,
    max_pages: usize,
    max_page_bytes: usize,
    max_native_row_bytes: usize,
    max_inline_novel_bytes: usize,
}

impl TraceSettingsBinding {
    fn for_profile(profile: RouterTraceProfile) -> Option<Self> {
        profile.version().map(|version| Self {
            profile,
            version,
            max_trace_bytes: MAX_ROUTER_TRACE_BYTES,
            max_pages: MAX_ROUTER_TRACE_PAGES,
            max_page_bytes: MAX_ROUTER_TRACE_PAGE_BYTES,
            max_native_row_bytes: 8 * 1024 * 1024,
            max_inline_novel_bytes: 256 * 1024,
        })
    }
}

/// Explicit host-only declaration. Parsing never verifies assets or starts a model.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HybridConfig {
    pub(super) encoder: LocalEmbeddingConfig,
    pub(super) limits: OwnedHybridLimits,
}

impl HybridConfig {
    /// Pure pinned profile derivation; actual files are checked by the owned launcher.
    pub(super) fn embedding_profile(&self) -> CliResult<TextEmbeddingProfile> {
        Ok(TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(
            embedding_backend_artifacts_digest(&self.encoder.runtime_artifacts)?,
        ))
    }

    fn validate(&self) -> CliResult<()> {
        if !self.encoder.program.is_absolute()
            || !self.encoder.model.is_absolute()
            || self.encoder.port == 0
        {
            return Err(invalid(
                "hybrid encoder requires absolute paths and a nonzero port",
            ));
        }
        self.limits.validate()?;
        if self.limits.segments.is_some() {
            return Err(invalid(
                "segmented queries require an embedded maintenance host; CLI segment maintenance is not available yet",
            ));
        }
        self.embedding_profile()?.validate()?;
        Ok(())
    }

    fn binding(&self) -> CliResult<HybridSettingsBinding<'_>> {
        let embedding_profile = self.embedding_profile()?;
        let embedding_profile_digest = embedding_profile.digest()?;
        let routed = self.limits.routed.is_some();
        Ok(HybridSettingsBinding {
            profile: if routed {
                "contextdb.cli-owned-routed-hybrid-settings.v1"
            } else {
                "contextdb.cli-owned-hybrid-settings.v1"
            },
            encoder: &self.encoder,
            embedding_profile,
            embedding_profile_digest,
            limits: self.limits,
            preparation: if routed {
                preparation::ROUTED_PROFILE
            } else {
                preparation::HYBRID_PROFILE
            },
            projection_limits: if routed {
                (
                    preparation::ROUTED_BATCH_EVENTS,
                    preparation::ROUTED_MAX_BATCHES,
                )
            } else {
                (
                    preparation::HYBRID_BATCH_EVENTS,
                    preparation::HYBRID_MAX_BATCHES,
                )
            },
            startup: HybridAllowanceBinding {
                max_work: super::HYBRID_STARTUP_MAX_WORK,
                max_bytes: super::HYBRID_STARTUP_MAX_BYTES,
                timeout_millis: super::HYBRID_STARTUP_TIME_MS,
            },
            shutdown: HybridAllowanceBinding {
                max_work: super::HYBRID_SHUTDOWN_MAX_WORK,
                max_bytes: super::HYBRID_SHUTDOWN_MAX_BYTES,
                timeout_millis: super::HYBRID_SHUTDOWN_TIME_MS,
            },
            maintenance: routed.then_some(HybridAllowanceBinding {
                max_work: super::ROUTED_MAINTENANCE_MAX_WORK,
                max_bytes: super::ROUTED_MAINTENANCE_MAX_BYTES,
                timeout_millis: super::ROUTED_MAINTENANCE_TIME_MS,
            }),
        })
    }
}

#[derive(Serialize)]
struct HybridSettingsBinding<'a> {
    profile: &'static str,
    encoder: &'a LocalEmbeddingConfig,
    embedding_profile: TextEmbeddingProfile,
    embedding_profile_digest: ContentDigest,
    limits: OwnedHybridLimits,
    preparation: &'static str,
    projection_limits: (u32, u8),
    startup: HybridAllowanceBinding,
    shutdown: HybridAllowanceBinding,
    #[serde(skip_serializing_if = "Option::is_none")]
    maintenance: Option<HybridAllowanceBinding>,
}

#[derive(Serialize)]
struct HybridAllowanceBinding {
    max_work: u64,
    max_bytes: u64,
    timeout_millis: u64,
}

#[derive(Serialize)]
struct SettingsBinding<'a> {
    profile: &'static str,
    control: &'a [OutgoingMessage],
    purpose: PackPurpose,
    memory_budget: &'a ContextBudgets,
    outgoing_budget: &'a OutgoingBudget,
    rolling: (u32, u32, usize, usize, u8),
    automatic_recall_filter: &'a RawFilter,
    cache_residency: &'static str,
    tools: &'static str,
    preparation: &'static str,
    raw_projection_limits: (u32, u8),
    #[serde(skip_serializing_if = "Option::is_none")]
    router_trace: Option<TraceSettingsBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    development_kev: Option<PolicyBinding<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    automatic_hybrid: Option<HybridSettingsBinding<'a>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostIdentity {
    workspace_id: WorkspaceId,
    session_id: SessionId,
    run_id: AgentRunId,
    actor_id: ActorId,
    agent_id: AgentId,
    subject_id: MemorySubjectId,
    scopes: BTreeSet<ScopeId>,
}

impl HostIdentity {
    fn owned(&self) -> OwnedRunIdentity {
        OwnedRunIdentity {
            workspace_id: self.workspace_id,
            session_id: self.session_id,
            run_id: self.run_id,
            actor_id: self.actor_id.to_string(),
            agent_id: self.agent_id.to_string(),
            subject_id: self.subject_id.to_string(),
            scopes: self.scopes.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostConfig {
    schema_version: u16,
    identity: HostIdentity,
    control: String,
    input_tokens: u32,
    pub(super) reader: LocalReaderConfig,
    #[serde(default, skip_serializing_if = "RouterTraceProfile::is_off")]
    router_trace_profile: RouterTraceProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) development_kev: Option<KevConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) automatic_hybrid: Option<HybridConfig>,
}

impl HostConfig {
    pub(super) fn read(path: &Path) -> CliResult<Self> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| invalid("trusted conversation configuration is unavailable"))?
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid("trusted conversation configuration cannot be read"))?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(invalid(
                "trusted conversation configuration exceeds 128 KiB",
            ));
        }
        let config: Self = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("invalid trusted conversation configuration"))?;
        config.validate()?;
        Ok(config)
    }

    pub(super) fn identity(&self) -> OwnedRunIdentity {
        self.identity.owned()
    }

    fn validate(&self) -> CliResult<()> {
        let profile = &self.reader.model_profile;
        profile
            .validate()
            .map_err(|_| invalid("invalid local reader model profile"))?;
        if self.schema_version != 1
            || self.identity.scopes.is_empty()
            || self.identity.scopes.len() > 32
            || self.control.is_empty()
            || self.control.len() > 64 * 1024
            || !(256..=65_536).contains(&self.input_tokens)
            || self
                .input_tokens
                .checked_add(128)
                .is_none_or(|tokens| tokens > profile.available_input_tokens())
            || profile.max_context_tokens > 131_072
            || profile.external_processing
            || profile.supports_tool_results
            || !self.reader.program.is_absolute()
            || !self.reader.program.is_file()
            || self.reader.args.len() > 32
            || self
                .reader
                .args
                .iter()
                .any(|argument| argument.len() > 4096 || argument.contains('\0'))
            || self.reader.args.iter().map(String::len).sum::<usize>() > 64 * 1024
            || !(100..=120_000).contains(&self.reader.timeout_millis)
        {
            return Err(invalid(
                "configuration exceeds the bounded local conversation profile",
            ));
        }
        if let Some(hybrid) = &self.automatic_hybrid {
            if self.router_trace_profile != RouterTraceProfile::RequiredReplayV2
                || self.development_kev.is_some()
            {
                return Err(invalid(
                    "automatic hybrid requires replay v2 and a separate development Kev configuration",
                ));
            }
            hybrid.validate()?;
        }
        if let Some(kev) = &self.development_kev {
            if self.router_trace_profile.is_off() {
                return Err(invalid(
                    "development Kev requires protected whole-frontier preparation",
                ));
            }
            kev.validate()?;
        }
        let settings = self.settings()?;
        settings.rolling.validate(self.input_tokens)?;
        Ok(())
    }

    /// Canonical parsed values bind defaults and every reader/settings field.
    pub(super) fn digest(&self) -> CliResult<String> {
        Ok(blake3::hash(&self.binding_bytes()?).to_hex().to_string())
    }

    fn binding_bytes(&self) -> CliResult<Vec<u8>> {
        let settings = self.settings()?;
        let binding = SettingsBinding {
            profile: "contextdb.cli-owned-host-settings.v1",
            control: &settings.control,
            purpose: settings.purpose,
            memory_budget: &settings.memory_budget,
            outgoing_budget: &settings.outgoing_budget,
            rolling: (
                settings.rolling.high_tokens,
                settings.rolling.low_tokens,
                settings.rolling.keep_complete_groups,
                settings.rolling.chunk_groups,
                settings.rolling.max_prepare_attempts,
            ),
            automatic_recall_filter: &settings.automatic_recall_filter,
            cache_residency: "disabled",
            tools: "no-external-tools",
            preparation: preparation::PROFILE,
            raw_projection_limits: (preparation::BATCH_EVENTS, preparation::MAX_BATCHES),
            router_trace: TraceSettingsBinding::for_profile(self.router_trace_profile),
            development_kev: self.development_kev.as_ref().map(KevConfig::binding),
            automatic_hybrid: self
                .automatic_hybrid
                .as_ref()
                .map(HybridConfig::binding)
                .transpose()?,
        };
        serde_json::to_vec(&(self, binding))
            .map_err(|_| invalid("conversation configuration cannot be bound"))
    }

    pub(super) fn settings(&self) -> CliResult<RuntimeSettings> {
        Ok(RuntimeSettings {
            control: vec![OutgoingMessage {
                id: BlockId::new("owned-host-control")
                    .map_err(|_| invalid("invalid host control identity"))?,
                zone: OutgoingZone::Control,
                role: OutgoingRole::System,
                text: self.control.clone(),
                originals: vec![],
                tool_calls: vec![],
                tool_result: None,
            }],
            purpose: PackPurpose::Conversation,
            memory_budget: ContextBudgets {
                // Recall may cross its soft target to fit an exact source and
                // its attribution. The complete encoded request remains capped.
                hard_tokens: self.input_tokens,
                soft_tokens: self.input_tokens / 2,
                max_blocks: 48,
                max_evidence_blocks: 64,
                max_raw_evidence_tokens: self.input_tokens,
                max_history_tokens: self.input_tokens,
                max_conflict_tokens: self.input_tokens,
                max_serialized_bytes: 2 * 1024 * 1024,
                max_selection_evaluations: 96,
            },
            outgoing_budget: OutgoingBudget {
                max_input_tokens: self.input_tokens,
                safety_tokens: 128,
                max_wire_bytes: 2 * 1024 * 1024,
            },
            rolling: RollingPolicy {
                high_tokens: self.input_tokens * 3 / 4,
                low_tokens: self.input_tokens / 2,
                keep_complete_groups: 1,
                chunk_groups: 2,
                max_prepare_attempts: 3,
            },
            cache_residency: None,
            automatic_recall_filter: RawFilter::default(),
            automatic_bm25: None,
            automatic_hybrid: None,
            router_trace_profile: self.router_trace_profile,
        })
    }
}
