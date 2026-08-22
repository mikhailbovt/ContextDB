//! Provider-neutral runtime adapters.

use std::fmt;

use contextdb_context::CompiledContext;
use serde::Serialize;

use crate::{ChatText, Result};

/// Provider-neutral input with explicit trust channels.
#[derive(Clone)]
pub struct SeparatedRuntimeInput {
    /// Compiler-generated trusted controls, never retrieved payload.
    pub trusted_control: String,
    /// Retrieved memory represented only as untrusted data.
    pub untrusted_memory: String,
    /// Current user content, independently framed.
    pub user_message: String,
    /// Canonical ContextPack digest, if memory was admitted.
    pub context_digest: Option<String>,
}

impl fmt::Debug for SeparatedRuntimeInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SeparatedRuntimeInput")
            .field("trusted_control_bytes", &self.trusted_control.len())
            .field("untrusted_memory_bytes", &self.untrusted_memory.len())
            .field("user_message_bytes", &self.user_message.len())
            .field("context_digest", &self.context_digest)
            .finish()
    }
}

/// Provider-neutral single-prompt input. JSON encoding prevents memory text
/// from escaping its untrusted-data field by imitating delimiters.
#[derive(Clone)]
pub struct SinglePromptRuntimeInput {
    /// Serialized prompt envelope.
    pub prompt: String,
    /// Canonical ContextPack digest, if memory was admitted.
    pub context_digest: Option<String>,
}

impl fmt::Debug for SinglePromptRuntimeInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SinglePromptRuntimeInput")
            .field("prompt_bytes", &self.prompt.len())
            .field("context_digest", &self.context_digest)
            .finish()
    }
}

/// Runtime-specific prepared input. Neither variant can mutate memory.
#[derive(Clone, Debug)]
pub enum PreparedRuntimeInput {
    /// Runtime supports separate instruction, memory-data, and user channels.
    Separated(SeparatedRuntimeInput),
    /// Runtime accepts one prompt string.
    SinglePrompt(SinglePromptRuntimeInput),
}

/// Narrow runtime formatting seam. It intentionally contains no provider call,
/// API key, model SDK, extraction, or mutation capability.
pub trait ConversationRuntimeAdapter: Send + Sync {
    /// Formats current input and an optional validated ContextPack.
    fn prepare(
        &self,
        user_message: &ChatText,
        context: Option<&CompiledContext>,
    ) -> Result<PreparedRuntimeInput>;
}

/// Adapter for chat runtimes with native separated channels.
#[derive(Clone, Copy, Debug, Default)]
pub struct SeparatedChannelsAdapter;

impl ConversationRuntimeAdapter for SeparatedChannelsAdapter {
    fn prepare(
        &self,
        user_message: &ChatText,
        context: Option<&CompiledContext>,
    ) -> Result<PreparedRuntimeInput> {
        let (trusted_control, untrusted_memory, context_digest) = context.map_or_else(
            || (String::new(), String::new(), None),
            |compiled| {
                (
                    compiled.rendered.trusted_control.clone(),
                    compiled.rendered.untrusted_data.clone(),
                    Some(compiled.canonical_digest.clone()),
                )
            },
        );
        Ok(PreparedRuntimeInput::Separated(SeparatedRuntimeInput {
            trusted_control,
            untrusted_memory,
            user_message: user_message.as_str().to_owned(),
            context_digest,
        }))
    }
}

/// Adapter for runtimes exposing a single string prompt.
#[derive(Clone, Copy, Debug, Default)]
pub struct SinglePromptJsonAdapter;

#[derive(Serialize)]
struct SinglePromptEnvelope<'a> {
    schema: &'static str,
    trusted_control: &'a str,
    untrusted_memory_data: &'a str,
    user_message: &'a str,
}

impl ConversationRuntimeAdapter for SinglePromptJsonAdapter {
    fn prepare(
        &self,
        user_message: &ChatText,
        context: Option<&CompiledContext>,
    ) -> Result<PreparedRuntimeInput> {
        let (trusted_control, untrusted_memory, context_digest) = context.map_or_else(
            || ("", "", None),
            |compiled| {
                (
                    compiled.rendered.trusted_control.as_str(),
                    compiled.rendered.untrusted_data.as_str(),
                    Some(compiled.canonical_digest.clone()),
                )
            },
        );
        let prompt = serde_json::to_string(&SinglePromptEnvelope {
            schema: "contextdb.chat.single-prompt.v1",
            trusted_control,
            untrusted_memory_data: untrusted_memory,
            user_message: user_message.as_str(),
        })?;
        Ok(PreparedRuntimeInput::SinglePrompt(
            SinglePromptRuntimeInput {
                prompt,
                context_digest,
            },
        ))
    }
}
