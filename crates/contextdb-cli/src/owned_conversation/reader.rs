//! Buffered text reader; the host owns the conversation and the exact wire.

use std::{path::PathBuf, sync::Mutex};

use contextdb_agent_runtime::{
    ModelReconciliation, PartialReaderOutput, ReaderAdapter, ReaderCapabilities, ReaderHistory,
    ReaderOutcome, ReaderReply, ReaderUsage,
};
use contextdb_context::{
    ContextError, EncodedOutgoing, ModelProfile, OutgoingEncoder, OutgoingMessage, OutgoingRole,
    RequestCountKind, TokenCounter,
};
use contextdb_core::{ContentDigest, ModelCallId, ModelRequestManifest, RequestPart};
use contextdb_recall::QueryBudget;
use contextdb_service::{ErrorCode, ServiceError, ServiceResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::CliResult;

mod transport;
use transport::Bridge;

const ENCODER: &str = "llama.cpp.qwen3-chatml-json.v1";
const MAX_WIRE: usize = 2 * 1024 * 1024;
const MAX_OUTPUT: usize = 256 * 1024;

/// Trusted launch configuration, never accepted from conversation input.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalReaderConfig {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub model_profile: ModelProfile,
    #[serde(default = "default_seed")]
    pub seed: u32,
    #[serde(default = "default_timeout")]
    pub timeout_millis: u64,
}
fn default_seed() -> u32 {
    17
}
fn default_timeout() -> u64 {
    120_000
}
impl std::fmt::Debug for LocalReaderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalReaderConfig")
            .field("model_profile", &self.model_profile.id)
            .field("timeout_millis", &self.timeout_millis)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(super) struct LocalReader {
    bridge: Bridge,
    profile: ModelProfile,
    seed: u32,
    usage: Mutex<Option<(ModelCallId, ReaderUsage)>>,
}
impl LocalReader {
    pub(super) fn spawn(config: LocalReaderConfig) -> CliResult<Self> {
        config.model_profile.validate().map_err(context_service)?;
        if config.model_profile.supports_tool_results || config.model_profile.external_processing {
            return Err(
                unavailable("local text reader excludes tools and external processing").into(),
            );
        }
        let bridge = Bridge::spawn(&config)?;
        let reader = Self {
            bridge,
            profile: config.model_profile,
            seed: config.seed,
            usage: Mutex::default(),
        };
        let hello = reader.bridge.exchange(&json!({
            "op":"hello", "profile":reader.profile,
            "encoder":ENCODER, "tokenizer":reader.profile.tokenizer_id
        }))?;
        let value: Value = hello.value()?;
        let profile: ModelProfile = serde_json::from_value(value["profile"].clone())
            .map_err(|_| unavailable("reader profile handshake failed"))?;
        if profile != reader.profile
            || value["encoder"] != ENCODER
            || value["tokenizer"] != reader.profile.tokenizer_id
        {
            return Err(
                unavailable("reader handshake differs from the configured contract").into(),
            );
        }
        Ok(reader)
    }

    pub(super) fn model_profile(&self) -> &ModelProfile {
        &self.profile
    }

    /// One deadline spans all tokenizer, encoder and completion IO for this turn.
    pub(super) fn begin_turn(&self) -> CliResult<()> {
        self.bridge.begin_turn().map_err(Into::into)
    }

    fn parts(
        &self,
        messages: &[OutgoingMessage],
    ) -> contextdb_context::Result<(Vec<RequestPart>, Vec<u8>)> {
        let mut parts = Vec::new();
        let mut prompt = String::new();
        for message in messages {
            if message.text.contains("<|im_")
                || message.text.contains("<|endoftext|>")
                || !message.tool_calls.is_empty()
                || message.tool_result.is_some()
            {
                return Err(invalid("unsupported ChatML data or tool protocol"));
            }
            let role = match message.role {
                OutgoingRole::System | OutgoingRole::Developer => "system",
                OutgoingRole::Assistant => "assistant",
                OutgoingRole::User => "user",
                OutgoingRole::Tool => {
                    return Err(invalid("local text reader excludes tool protocol"));
                }
            };
            let header = format!("<|im_start|>{role}\n");
            append_prompt(&mut prompt, &header)?;
            append_prompt(&mut prompt, &message.text)?;
            append_prompt(&mut prompt, "<|im_end|>\n")?;
            novel(&mut parts, &header)?;
            let mut offset = 0;
            for original in &message.originals {
                let start = original.text_start as usize;
                let end = original.text_end as usize;
                novel(
                    &mut parts,
                    message
                        .text
                        .get(offset..start)
                        .ok_or_else(|| invalid("source ordering"))?,
                )?;
                let source = message
                    .text
                    .get(start..end)
                    .ok_or_else(|| invalid("source bounds"))?;
                let escaped =
                    serde_json::to_string(source).map_err(|_| invalid("source encoding failed"))?;
                let bytes = &escaped.as_bytes()[1..escaped.len() - 1];
                parts.push(RequestPart::JsonStringSource {
                    span: original.span.clone(),
                    byte_length: bytes.len() as u64,
                    digest: ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes()),
                });
                offset = end;
                check_parts(&parts)?;
            }
            novel(
                &mut parts,
                message
                    .text
                    .get(offset..)
                    .ok_or_else(|| invalid("source bounds"))?,
            )?;
            novel(&mut parts, "<|im_end|>\n")?;
        }
        let suffix = "<|im_start|>assistant\n<think>\n\n</think>\n\n";
        append_prompt(&mut prompt, suffix)?;
        novel(&mut parts, suffix)?;
        parts.insert(
            0,
            RequestPart::Novel {
                bytes: b"{\"prompt\":\"".to_vec(),
            },
        );
        let options = format!(
            "\",\"n_predict\":{},\"temperature\":0.7,\"top_k\":20,\"top_p\":0.8,\"min_p\":0,\"presence_penalty\":1.5,\"seed\":{},\"cache_prompt\":true,\"id_slot\":0,\"stream\":false}}",
            self.profile.reserved_output_tokens, self.seed
        );
        parts.push(RequestPart::Novel {
            bytes: options.as_bytes().to_vec(),
        });
        check_parts(&parts)?;
        let mut wire = b"{\"prompt\":".to_vec();
        wire.extend(serde_json::to_vec(&prompt).map_err(|_| invalid("prompt encoding failed"))?);
        wire.extend_from_slice(&options.as_bytes()[1..]);
        if wire.len() > MAX_WIRE {
            return Err(invalid("local reader wire exceeds 2 MiB"));
        }
        Ok((parts, wire))
    }
}

fn append_prompt(prompt: &mut String, text: &str) -> contextdb_context::Result<()> {
    if text.len() > MAX_WIRE.saturating_sub(prompt.len()) {
        return Err(invalid("local reader prompt exceeds 2 MiB"));
    }
    prompt.push_str(text);
    Ok(())
}
fn check_parts(parts: &[RequestPart]) -> contextdb_context::Result<()> {
    if parts.len() > 512 {
        return Err(invalid("local reader source manifest exceeds 512 parts"));
    }
    Ok(())
}
fn novel(parts: &mut Vec<RequestPart>, text: &str) -> contextdb_context::Result<()> {
    let escaped =
        serde_json::to_string(text).map_err(|_| invalid("prompt part encoding failed"))?;
    parts.push(RequestPart::Novel {
        bytes: escaped.as_bytes()[1..escaped.len() - 1].to_vec(),
    });
    check_parts(parts)
}
fn invalid(message: &'static str) -> ContextError {
    ContextError::InvalidRequest(message.into())
}
fn unavailable(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::ProviderUnavailable, message, false)
}
fn context_service(_: ContextError) -> ServiceError {
    unavailable("local reader profile or encoding failed")
}

impl TokenCounter for LocalReader {
    #[allow(
        clippy::misnamed_getters,
        reason = "the counter identifies its tokenizer"
    )]
    fn id(&self) -> &str {
        &self.profile.tokenizer_id
    }
    fn count_tokens(&self, text: &str) -> contextdb_context::Result<u32> {
        if text.len() > MAX_WIRE {
            return Err(invalid("tokenizer text exceeds local wire bound"));
        }
        let reply = self
            .bridge
            .exchange(&json!({"op":"tokenize","text":text,"special":false}))
            .and_then(|frame| frame.value())
            .map_err(|_| invalid("local tokenizer exchange failed"))?;
        count(&reply)
    }
}
fn count(value: &Value) -> contextdb_context::Result<u32> {
    value
        .get("count")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| invalid("local tokenizer count absent or invalid"))
}
impl OutgoingEncoder for LocalReader {
    fn id(&self) -> &str {
        ENCODER
    }
    fn tokenizer_id(&self) -> &str {
        &self.profile.tokenizer_id
    }
    fn encode(
        &self,
        messages: &[OutgoingMessage],
        budget: &mut QueryBudget,
    ) -> contextdb_context::Result<EncodedOutgoing> {
        let (_, wire) = self.parts(messages)?;
        budget
            .charge(1, wire.len() as u64)
            .map_err(|_| invalid("encoder budget exhausted"))?;
        let value: Value =
            serde_json::from_slice(&wire).map_err(|_| invalid("encoded prompt invalid"))?;
        let response = self
            .bridge
            .exchange(&json!({"op":"tokenize","text":value["prompt"],"special":true}))
            .and_then(|frame| frame.value())
            .map_err(|_| invalid("complete prompt tokenizer exchange failed"))?;
        budget
            .check()
            .map_err(|_| invalid("encoder deadline exhausted"))?;
        Ok(EncodedOutgoing {
            protocol: ENCODER.into(),
            tokenizer: self.profile.tokenizer_id.clone(),
            count_kind: RequestCountKind::Exact,
            input_tokens: count(&response)?,
            wire,
        })
    }
}
impl ReaderAdapter for LocalReader {
    fn profile(&self) -> ModelProfile {
        self.profile.clone()
    }
    fn capabilities(&self) -> ReaderCapabilities {
        ReaderCapabilities { history:ReaderHistory::Stateless, can_reconcile:false,
            history_contract:"local llama.cpp completion receives only the complete captured prompt; context shift is disabled; KV reuse attaches no conversation messages".into() }
    }
    fn tokenizer(&self) -> &dyn TokenCounter {
        self
    }
    fn capture_manifest(
        &self,
        call: ModelCallId,
        messages: &[OutgoingMessage],
        wire: &EncodedOutgoing,
        budget: &mut QueryBudget,
    ) -> ServiceResult<ModelRequestManifest> {
        let (parts, expected) = self.parts(messages).map_err(context_service)?;
        budget
            .charge(1, expected.len() as u64)
            .map_err(|_| unavailable("manifest budget exhausted"))?;
        if expected != wire.wire
            || wire.protocol != ENCODER
            || wire.tokenizer != self.profile.tokenizer_id
        {
            return Err(unavailable("capture differs from the exact reader wire"));
        }
        Ok(ModelRequestManifest {
            model_call_id: call,
            renderer: ENCODER.into(),
            wire_digest: ContentDigest::from_bytes(*blake3::hash(&expected).as_bytes()),
            byte_length: expected.len() as u64,
            parts,
        })
    }
    fn complete(
        &self,
        call: ModelCallId,
        outgoing: &EncodedOutgoing,
    ) -> ServiceResult<ReaderOutcome> {
        if outgoing.wire.len() > MAX_WIRE
            || outgoing.protocol != ENCODER
            || outgoing.tokenizer != self.profile.tokenizer_id
        {
            return Err(unavailable(
                "reader dispatch differs from configured wire contract",
            ));
        }
        *self
            .usage
            .lock()
            .map_err(|_| unavailable("reader usage state unavailable"))? =
            Some((call, ReaderUsage::default()));
        let frame = self
            .bridge
            .exchange(&json!({"op":"complete","call":call,"outgoing":outgoing}))?;
        if !frame.complete {
            return Ok(ReaderOutcome::Interrupted(PartialReaderOutput {
                bytes: frame.bytes.into_iter().take(MAX_OUTPUT).collect(),
                media_type: "application/json".into(),
            }));
        }
        let value: Value = match serde_json::from_slice(&frame.bytes) {
            Ok(value) => value,
            Err(_) => {
                return Ok(ReaderOutcome::Interrupted(PartialReaderOutput {
                    bytes: frame.bytes.into_iter().take(MAX_OUTPUT).collect(),
                    media_type: "application/json".into(),
                }));
            }
        };
        if let Some(partial) = value.get("partial") {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Partial {
                bytes: Vec<u8>,
                media_type: String,
            }
            let partial = match serde_json::from_value::<Partial>(partial.clone()) {
                Ok(partial)
                    if matches!(
                        partial.media_type.as_str(),
                        "application/json" | "text/plain; charset=utf-8"
                    ) =>
                {
                    partial
                }
                _ => {
                    return Ok(ReaderOutcome::Interrupted(PartialReaderOutput {
                        bytes: frame.bytes.into_iter().take(MAX_OUTPUT).collect(),
                        media_type: "application/json".into(),
                    }));
                }
            };
            return Ok(ReaderOutcome::Interrupted(PartialReaderOutput {
                bytes: partial.bytes.into_iter().take(MAX_OUTPUT).collect(),
                media_type: partial.media_type,
            }));
        }
        let text = value
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| unavailable("reader returned no visible output"))?;
        let mut completed = value.get("completed").and_then(Value::as_bool) == Some(true)
            && value.get("error").is_none();
        let usage = match value.get("usage").filter(|v| !v.is_null()) {
            None => ReaderUsage::default(),
            Some(value) => match serde_json::from_value::<ReaderUsage>(value.clone()) {
                Ok(usage) if usage.validate().is_ok() => usage,
                _ => {
                    completed = false;
                    ReaderUsage::default()
                }
            },
        };
        if let Ok(mut state) = self.usage.lock() {
            *state = Some((call, usage));
        }
        if text.len() > MAX_OUTPUT {
            let mut end = MAX_OUTPUT;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            return Ok(ReaderOutcome::Interrupted(PartialReaderOutput {
                bytes: text.as_bytes()[..end].to_vec(),
                media_type: "text/plain; charset=utf-8".into(),
            }));
        }
        if !completed {
            return Ok(ReaderOutcome::Interrupted(PartialReaderOutput {
                bytes: text.as_bytes().to_vec(),
                media_type: "text/plain; charset=utf-8".into(),
            }));
        }
        Ok(ReaderOutcome::Completed(ReaderReply::text(text)))
    }
    fn usage(&self, call: ModelCallId) -> ReaderUsage {
        self.usage
            .lock()
            .ok()
            .and_then(|value| {
                value
                    .as_ref()
                    .filter(|(id, _)| *id == call)
                    .map(|(_, usage)| usage.clone())
            })
            .unwrap_or_default()
    }
    fn reconcile(&self, _: ModelCallId, _: ContentDigest) -> ServiceResult<ModelReconciliation> {
        Ok(ModelReconciliation::Unknown)
    }
}
