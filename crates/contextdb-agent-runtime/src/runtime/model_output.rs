//! Preserve observed provider output before updating the executable protocol.

use super::*;
use crate::PartialReaderOutput;

impl<S: OwnedRunPort + PrepareContextPort + PayloadPort + ?Sized> OwnedAgentRuntime<S> {
    pub(super) fn validate_reader_protocol(&self, profile: &ModelProfile) -> ServiceResult<()> {
        if !profile.supports_tool_results
            && self
                .state
                .groups
                .iter()
                .flat_map(|group| &group.messages)
                .any(|message| !message.tool_calls.is_empty() || message.tool_result.is_some())
        {
            return Err(invalid(
                "reader cannot represent the retained tool protocol",
            ));
        }
        Ok(())
    }

    pub(super) fn capture_reply(
        &mut self,
        call: &PendingModelCall,
        reply: &ReaderReply,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<CaptureReceipt> {
        let protocol = !reply.tool_calls.is_empty();
        let text = if protocol {
            serde_json::to_string(reply).map_err(|_| invalid("model protocol cannot be encoded"))?
        } else {
            reply.text.clone()
        };
        let mut calls: BTreeSet<_> = self
            .state
            .groups
            .iter()
            .flat_map(|group| &group.messages)
            .flat_map(|message| &message.tool_calls)
            .cloned()
            .collect();
        if reply.tool_calls.len() > 32
            || (protocol && !self.state.model_profile.supports_tool_results)
            || reply
                .tool_calls
                .iter()
                .any(|tool| !calls.insert(tool.call_id.to_string()))
        {
            self.capture_interruption(
                call,
                PartialReaderOutput {
                    bytes: text.into_bytes(),
                    media_type: "application/json".into(),
                },
                now,
                budget,
            )?;
            return Err(invalid(
                "captured model protocol is invalid for this reader or repeats a call ID",
            ));
        }
        let mut request = self.event(
            EventKind::ModelResponseCompleted,
            EventRole::Assistant,
            text,
            now,
            ObservationId::new(),
        )?;
        request.event.parent_event_ids.insert(call.request_event);
        request.event.provenance = Some(EventProvenance::ModelOutput {
            model_call_id: call.call_id,
            request_event_id: call.request_event,
            format: if protocol {
                ModelOutputFormat::ProtocolJson
            } else {
                ModelOutputFormat::PlainText
            },
            tool_calls: reply.tool_calls.iter().map(|tool| tool.call_id).collect(),
        });
        self.pending_capture = Some(PendingCapture::Conversation(request));
        let receipt = self.flush_capture(budget)?;
        self.save_checkpoint(now, budget)?;
        Ok(receipt)
    }

    pub(super) fn capture_interruption(
        &mut self,
        call: &PendingModelCall,
        output: PartialReaderOutput,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<CaptureReceipt> {
        let mut request = self.event(
            EventKind::ModelResponseAborted,
            EventRole::Assistant,
            String::new(),
            now,
            ObservationId::new(),
        )?;
        request.event.payload = EventPayload::InlineBytes {
            digest: ContentDigest::from_bytes(*blake3::hash(&output.bytes).as_bytes()),
            bytes: output.bytes,
            media_type: output.media_type,
        };
        request.event.coverage = EventCoverage::PartialObservation;
        request.event.gap_reason =
            Some("provider output incomplete or protocol unsupported".into());
        request.event.parent_event_ids.insert(call.request_event);
        request.event.provenance = Some(EventProvenance::ModelOutput {
            model_call_id: call.call_id,
            request_event_id: call.request_event,
            format: ModelOutputFormat::OpaquePartial,
            tool_calls: vec![],
        });
        self.pending_capture = Some(PendingCapture::Conversation(request));
        let receipt = self.flush_capture(budget)?;
        self.save_checkpoint(now, budget)?;
        Ok(receipt)
    }
}
