//! Benchmark-only local ChatML transport. Python owns HTTP and complete run accounting.

use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

use contextdb_agent_runtime::*;
use contextdb_context::*;
use contextdb_core::*;
use contextdb_recall::QueryBudget;
use contextdb_service::{ErrorCode, ServiceError, ServiceResult};
use serde_json::{Value, json};

#[derive(Debug, Default)]
pub struct Bridge(Mutex<()>);
impl Bridge {
    pub fn exchange(&self, request: &Value) -> Result<Value> {
        let _guard = self.0.lock().map_err(error)?;
        let mut output = io::stdout().lock();
        serde_json::to_writer(&mut output, request).map_err(error)?;
        writeln!(output).map_err(error)?;
        output.flush().map_err(error)?;
        let mut line = String::new();
        io::stdin().read_line(&mut line).map_err(error)?;
        let value: Value = serde_json::from_str(&line).map_err(error)?;
        if value.get("error").is_some() {
            return Err(error("benchmark bridge failed"));
        }
        Ok(value)
    }
}

fn error(value: impl std::fmt::Display) -> ContextError {
    ContextError::InvalidRequest(value.to_string())
}
fn service_error(value: impl std::fmt::Display) -> ServiceError {
    ServiceError::new(ErrorCode::ProviderUnavailable, value.to_string(), false)
}

#[derive(Debug)]
pub struct LocalReader {
    pub bridge: Arc<Bridge>,
    pub profile: ModelProfile,
    pub seed: u32,
    usage: Mutex<Option<(ModelCallId, ReaderUsage)>>,
}
impl LocalReader {
    pub fn new(bridge: Arc<Bridge>, profile: ModelProfile, seed: u32) -> Self {
        Self {
            bridge,
            profile,
            seed,
            usage: Mutex::default(),
        }
    }

    fn parts(&self, messages: &[OutgoingMessage]) -> Result<(Vec<RequestPart>, Vec<u8>)> {
        let mut parts = vec![];
        let mut prompt = String::new();
        fn novel(parts: &mut Vec<RequestPart>, text: &str) -> Result<()> {
            let escaped = serde_json::to_string(text).map_err(error)?;
            parts.push(RequestPart::Novel {
                bytes: escaped.as_bytes()[1..escaped.len() - 1].to_vec(),
            });
            Ok(())
        }
        // This local benchmark profile rejects protocol delimiters in data, rather
        // than silently interpreting them as ChatML control or rewriting originals.
        for message in messages {
            if message.text.contains("<|im_")
                || message.text.contains("<|endoftext|>")
                || !message.tool_calls.is_empty()
                || message.tool_result.is_some()
            {
                return Err(error("unsupported ChatML data or tool protocol"));
            }
            let role = match message.role {
                OutgoingRole::System | OutgoingRole::Developer => "system",
                OutgoingRole::Assistant => "assistant",
                OutgoingRole::User => "user",
                OutgoingRole::Tool => return Err(error("text benchmark has no tool protocol")),
            };
            let header = format!("<|im_start|>{role}\n");
            prompt.push_str(&header);
            prompt.push_str(&message.text);
            prompt.push_str("<|im_end|>\n");
            novel(&mut parts, &header)?;
            let mut offset = 0;
            for original in &message.originals {
                let start = original.text_start as usize;
                let end = original.text_end as usize;
                let source = message
                    .text
                    .get(start..end)
                    .ok_or_else(|| error("source bounds"))?;
                novel(
                    &mut parts,
                    message
                        .text
                        .get(offset..start)
                        .ok_or_else(|| error("source ordering"))?,
                )?;
                let escaped = serde_json::to_string(source).map_err(error)?;
                let bytes = &escaped.as_bytes()[1..escaped.len() - 1];
                parts.push(RequestPart::JsonStringSource {
                    span: original.span.clone(),
                    byte_length: bytes.len() as u64,
                    digest: ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes()),
                });
                offset = end;
            }
            novel(&mut parts, &message.text[offset..])?;
            novel(&mut parts, "<|im_end|>\n")?;
        }
        let suffix = "<|im_start|>assistant\n<think>\n\n</think>\n\n";
        prompt.push_str(suffix);
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
            bytes: options.into_bytes(),
        });
        let mut wire = b"{\"prompt\":".to_vec();
        wire.extend(serde_json::to_vec(&prompt).map_err(error)?);
        if let Some(RequestPart::Novel { bytes }) = parts.last() {
            wire.extend_from_slice(&bytes[1..]);
        }
        Ok((parts, wire))
    }
}
impl TokenCounter for LocalReader {
    #[allow(
        clippy::misnamed_getters,
        reason = "TokenCounter identity is the tokenizer, not the reader"
    )]
    fn id(&self) -> &str {
        &self.profile.tokenizer_id
    }
    fn count_tokens(&self, text: &str) -> Result<u32> {
        let response = self
            .bridge
            .exchange(&json!({"op":"tokenize", "text":text, "special":false}))?;
        u32::try_from(
            response["count"]
                .as_u64()
                .ok_or_else(|| error("token count absent"))?,
        )
        .map_err(error)
    }
}
impl OutgoingEncoder for LocalReader {
    fn id(&self) -> &str {
        "llama.cpp.qwen3-chatml-json.v1"
    }
    fn tokenizer_id(&self) -> &str {
        &self.profile.tokenizer_id
    }
    fn encode(
        &self,
        messages: &[OutgoingMessage],
        budget: &mut QueryBudget,
    ) -> Result<EncodedOutgoing> {
        let (_, wire) = self.parts(messages)?;
        budget
            .charge(1, wire.len() as u64)
            .map_err(|_| error("encoder budget"))?;
        let value: Value = serde_json::from_slice(&wire).map_err(error)?;
        let count = self
            .bridge
            .exchange(&json!({"op":"tokenize", "text":value["prompt"], "special":true}))?;
        Ok(EncodedOutgoing {
            protocol: OutgoingEncoder::id(self).into(),
            tokenizer: self.profile.tokenizer_id.clone(),
            count_kind: RequestCountKind::Exact,
            input_tokens: u32::try_from(
                count["count"]
                    .as_u64()
                    .ok_or_else(|| error("count absent"))?,
            )
            .map_err(error)?,
            wire,
        })
    }
}
impl ReaderAdapter for LocalReader {
    fn profile(&self) -> ModelProfile {
        self.profile.clone()
    }
    fn capabilities(&self) -> ReaderCapabilities {
        ReaderCapabilities { history: ReaderHistory::Stateless, can_reconcile:false,
            history_contract:"llama.cpp /completion receives the complete captured prompt; KV reuse does not attach prior messages; context shifting disabled".into() }
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
        let (parts, expected) = self.parts(messages).map_err(service_error)?;
        budget
            .charge(1, expected.len() as u64)
            .map_err(|_| service_error("manifest allowance"))?;
        if expected != wire.wire || parts.len() > 512 {
            return Err(service_error("capture differs from actual wire"));
        }
        Ok(ModelRequestManifest {
            model_call_id: call,
            renderer: OutgoingEncoder::id(self).into(),
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
        let wire = std::str::from_utf8(&outgoing.wire).map_err(service_error)?;
        let response = self.bridge.exchange(&json!({"op":"complete", "call":call, "wire":wire, "expected_input":outgoing.input_tokens})).map_err(service_error)?;
        let usage = serde_json::from_value(response["usage"].clone()).unwrap_or_default();
        *self.usage.lock().map_err(service_error)? = Some((call, usage));
        let text = response["text"]
            .as_str()
            .ok_or_else(|| service_error("visible output absent"))?;
        if response["completed"] != true {
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
