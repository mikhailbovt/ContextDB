//! Trusted operator configuration, independent of the conversation protocol.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use contextdb_agent_runtime::{RollingPolicy, RuntimeSettings};
use contextdb_context::{
    BlockId, ContextBudgets, OutgoingBudget, OutgoingMessage, OutgoingRole, OutgoingZone,
    PackPurpose,
};
use contextdb_continuity::OwnedRunIdentity;
use contextdb_core::{
    ActorId, AgentId, AgentRunId, MemorySubjectId, RawFilter, ScopeId, SessionId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use super::invalid;
use super::preparation;
use super::reader::LocalReaderConfig;
use crate::CliResult;

const MAX_CONFIG_BYTES: u64 = 128 * 1024;

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
        let settings = self.settings()?;
        settings.rolling.validate(self.input_tokens)?;
        Ok(())
    }

    /// Canonical parsed values bind defaults and every reader/settings field.
    pub(super) fn digest(&self) -> CliResult<String> {
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
        };
        let bytes = serde_json::to_vec(&(self, binding))
            .map_err(|_| invalid("conversation configuration cannot be bound"))?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
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
        })
    }
}
