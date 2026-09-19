//! Explicit JSON source transforms for exact request-occurrence capture.

use super::*;
use contextdb_core::{ModelCallId, ModelRequestManifest, RequestPart};

impl ReferenceOutgoingEncoder<'_> {
    /// Build a provenance-preserving replay of the already encoded reference
    /// request. Only novel delimiters/metadata are stored again; source text is
    /// represented by a verified JSON-string transform of its immutable original.
    pub fn capture_manifest(
        &self,
        call: ModelCallId,
        messages: &[OutgoingMessage],
        outgoing: &EncodedOutgoing,
        budget: &mut QueryBudget,
    ) -> Result<ModelRequestManifest> {
        validate_protocol(messages)?;
        if outgoing.protocol != self.id() || outgoing.tokenizer != self.tokenizer_id() {
            return Err(crate::ContextError::InvalidRequest(
                "request capture profile differs".into(),
            ));
        }
        let mut parts = Vec::new();
        let mut replay = Vec::new();
        novel(&mut parts, &mut replay, b"[");
        for (index, message) in messages.iter().enumerate() {
            charge(budget, 1, message.text.len() as u64)?;
            if index != 0 {
                novel(&mut parts, &mut replay, b",");
            }
            let prefix = format!(
                "{{\"id\":{},\"zone\":{},\"role\":{},\"text\":\"",
                json(&message.id)?,
                json(&message.zone)?,
                json(&message.role)?
            );
            novel(&mut parts, &mut replay, prefix.as_bytes());
            let mut offset = 0;
            for original in &message.originals {
                let start = original.text_start as usize;
                let end = original.text_end as usize;
                novel(
                    &mut parts,
                    &mut replay,
                    &json_contents(&message.text[offset..start])?,
                );
                let bytes = json_contents(&message.text[start..end])?;
                replay.extend_from_slice(&bytes);
                parts.push(RequestPart::JsonStringSource {
                    span: original.span.clone(),
                    byte_length: bytes.len() as u64,
                    digest: ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()),
                });
                offset = end;
            }
            novel(
                &mut parts,
                &mut replay,
                &json_contents(&message.text[offset..])?,
            );
            let suffix = format!(
                "\",\"originals\":{},\"tool_calls\":{},\"tool_result\":{}}}",
                json(&message.originals)?,
                json(&message.tool_calls)?,
                json(&message.tool_result)?
            );
            novel(&mut parts, &mut replay, suffix.as_bytes());
        }
        novel(&mut parts, &mut replay, b"]");
        charge(budget, 1, replay.len() as u64)?;
        if parts.len() > 512 || replay != outgoing.wire {
            return Err(crate::ContextError::InvalidRequest(
                "request capture differs from wire or exceeds 512 parts".into(),
            ));
        }
        Ok(ModelRequestManifest {
            model_call_id: call,
            renderer: self.id().into(),
            wire_digest: ContentDigest::from_bytes(*blake3::hash(&replay).as_bytes()),
            byte_length: replay.len() as u64,
            parts,
        })
    }
}

fn json(value: &impl Serialize) -> Result<String> {
    serde_json::to_string(value).map_err(serialization)
}
fn json_contents(text: &str) -> Result<Vec<u8>> {
    let text = json(&text)?;
    Ok(text.as_bytes()[1..text.len() - 1].to_vec())
}
fn novel(parts: &mut Vec<RequestPart>, replay: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    replay.extend_from_slice(bytes);
    if let Some(RequestPart::Novel { bytes: previous }) = parts.last_mut() {
        previous.extend_from_slice(bytes);
    } else {
        parts.push(RequestPart::Novel {
            bytes: bytes.to_vec(),
        });
    }
}
