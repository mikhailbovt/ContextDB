// Native capture/checkpoint retries and source-addressed recovery.

use super::*;

impl<S: OwnedRunPort + PrepareContextPort + PayloadPort + ?Sized> OwnedAgentRuntime<S> {
    pub(super) fn event(
        &self,
        kind: EventKind,
        role: EventRole,
        text: String,
        now: TimestampMicros,
        id: ObservationId,
    ) -> ServiceResult<CaptureRequest> {
        Ok(CaptureRequest {
            context: self.context.clone(),
            idempotency_key: format!("run/{}/{id}", self.state.identity.run_id),
            event: EventEnvelope {
                version: EVENT_ENVELOPE_VERSION,
                event_id: id,
                workspace_id: self.state.identity.workspace_id,
                scope_ids: self.state.identity.scopes.clone(),
                producer_id: self.state.producer_id,
                producer_sequence: self.state.next_sequence,
                kind,
                recorded_at: now,
                observed_at: None,
                source_id: SourceId::from_uuid(id.as_uuid())
                    .map_err(|_| invalid("source identity invalid"))?,
                source_version: None,
                adapter_id: "contextdb.owned-conversation.v1".into(),
                role,
                session_id: Some(self.state.identity.session_id),
                run_id: Some(self.state.identity.run_id),
                task_id: None,
                parent_event_ids: BTreeSet::new(),
                supersedes_event_id: None,
                payload: EventPayload::InlineUtf8 {
                    digest: ContentDigest::from_bytes(*blake3::hash(text.as_bytes()).as_bytes()),
                    text,
                },
                coverage: EventCoverage::CompleteObservation,
                upstream_truncated: false,
                gap_reason: None,
                response_stream: None,
                provenance: None,
            },
        })
    }

    pub(super) fn flush_capture(
        &mut self,
        budget: &mut QueryBudget,
    ) -> ServiceResult<CaptureReceipt> {
        let pending = self
            .pending_capture
            .clone()
            .ok_or_else(|| invalid("no retained capture"))?;
        let request = pending.request().clone();
        let host = CaptureHost::new(Arc::clone(&self.owner));
        let receipt = match request.event.payload.clone() {
            EventPayload::InlineUtf8 { text, .. } => {
                charge(budget, 1, text.len() as u64)?;
                host.capture_bytes(
                    request,
                    text.into_bytes(),
                    "text/plain; charset=utf-8".into(),
                )?
                .receipt
            }
            EventPayload::Assembly { manifest } => {
                host.capture_model_request(request, manifest)?.receipt
            }
            _ => return Err(invalid("unsupported owned capture payload")),
        };
        let original = self.owner.read_original(ReadOriginalRequest {
            context: self.context.clone(),
            event_id: receipt.event_id,
            after_receipt: Some(receipt.clone()),
        })?;
        self.apply_original(&original)?;
        if let PendingCapture::ModelRequest { prepared, .. } = pending {
            self.phase = CallPhase::Captured {
                prepared,
                receipt: receipt.clone(),
            };
        }
        self.pending_capture = None;
        Ok(receipt)
    }

    pub(super) fn apply_original(&mut self, original: &CapturedOriginal) -> ServiceResult<()> {
        let event = &original.event;
        if event.producer_id != self.state.producer_id
            || event.producer_sequence != self.state.next_sequence
            || event.run_id != Some(self.state.identity.run_id)
            || event.session_id != Some(self.state.identity.session_id)
        {
            return Err(invalid(
                "captured runtime event is out of sequence or belongs to another run",
            ));
        }
        let metadata = RawSource::from(event);
        match (event.kind, event.role) {
            (EventKind::MessageCreated, EventRole::User) => {
                if self.state.pending_model.is_some()
                    || self
                        .state
                        .groups
                        .last()
                        .is_some_and(|group| !group.complete)
                {
                    return Err(invalid("captured user input interrupts pending work"));
                }
                let sequence = self
                    .state
                    .groups
                    .last()
                    .map_or(Some(1), |group| group.sequence.checked_add(1))
                    .ok_or_else(|| exhausted("interaction sequence exhausted"))?;
                self.state.groups.push(InteractionGroup {
                    sequence,
                    messages: vec![captured_message(&metadata, OutgoingRole::User)?],
                    complete: false,
                });
            }
            (EventKind::ModelRequested, EventRole::Host) => {
                let pending = self
                    .state
                    .pending_model
                    .as_mut()
                    .ok_or_else(|| invalid("request has no checkpointed model intent"))?;
                let EventPayload::Assembly { manifest } = &event.payload else {
                    return Err(invalid("owned model request has no exact wire"));
                };
                if event.event_id != pending.request_event
                    || manifest.model_call_id != pending.call_id
                {
                    return Err(invalid("captured request differs from model intent"));
                }
                pending.wire_digest = Some(manifest.wire_digest);
                self.phase = CallPhase::Unknown;
            }
            (EventKind::ModelResponseCompleted, EventRole::Assistant) => {
                let pending = self
                    .state
                    .pending_model
                    .as_ref()
                    .ok_or_else(|| invalid("response has no pending model attempt"))?;
                if pending.wire_digest.is_none()
                    || !event.parent_event_ids.contains(&pending.request_event)
                {
                    return Err(invalid("response has no matching captured request"));
                }
                let group = self
                    .state
                    .groups
                    .last_mut()
                    .ok_or_else(|| invalid("response has no interaction group"))?;
                if metadata.byte_length != Some(0) {
                    group
                        .messages
                        .push(captured_message(&metadata, OutgoingRole::Assistant)?);
                }
                group.complete = true;
                self.state.pending_model = None;
                self.phase = CallPhase::Ready;
            }
            _ => {
                return Err(ServiceError::new(
                    ErrorCode::Unsupported,
                    "capture tail requires another protocol adapter",
                    false,
                ));
            }
        }
        self.state.next_sequence = event
            .producer_sequence
            .checked_add(1)
            .ok_or_else(|| exhausted("producer sequence exhausted"))?;
        Ok(())
    }

    pub(super) fn save_checkpoint(
        &mut self,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if self.pending_checkpoint.is_none() {
            let mut checkpoint = self.state.clone();
            checkpoint.revision = checkpoint
                .revision
                .checked_add(1)
                .ok_or_else(|| exhausted("run revision exhausted"))?;
            checkpoint.next_sequence = checkpoint
                .next_sequence
                .checked_add(1)
                .ok_or_else(|| exhausted("producer sequence exhausted"))?;
            checkpoint.recorded_at = now;
            self.pending_checkpoint = Some(SaveRunCheckpointRequest {
                context: self.context.clone(),
                event_id: ObservationId::new(),
                idempotency_key: format!(
                    "run/{}/checkpoint/{}",
                    checkpoint.identity.run_id, checkpoint.revision
                ),
                expected_revision: self.state.revision,
                checkpoint,
            });
        }
        let request = self
            .pending_checkpoint
            .as_ref()
            .ok_or_else(|| invalid("checkpoint absent"))?
            .clone();
        let saved = self.owner.save_run_checkpoint(request, budget)?;
        self.state = saved.checkpoint;
        self.checkpoint_receipt = saved.receipt;
        self.pending_checkpoint = None;
        Ok(())
    }
}

fn captured_message(source: &RawSource, role: OutgoingRole) -> ServiceResult<CapturedMessage> {
    let size = source
        .byte_length
        .ok_or_else(|| invalid("original bytes are unavailable"))?;
    if size == 0 || size > 1024 * 1024 {
        return Err(exhausted(
            "captured message needs an explicit bounded range/media adapter",
        ));
    }
    let digest = source
        .payload_digest
        .ok_or_else(|| invalid("captured original digest absent"))?;
    Ok(CapturedMessage {
        id: BlockId::new(format!("event:{}", source.event_id)).map_err(context_error)?,
        source: OriginalSourceSpan {
            event_id: source.event_id,
            payload_digest: digest,
            start: 0,
            end: size,
            span_digest: digest,
        },
        role,
        tool_calls: vec![],
        tool_result: None,
    })
}
