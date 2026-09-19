use std::{
    io::Write,
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct FlakyOwner {
    owner: Arc<NativeService>,
    fail: std::sync::atomic::AtomicBool,
}

impl CapturePort for FlakyOwner {
    fn append_event_with_status(
        &self,
        request: contextdb_service::CaptureRequest,
    ) -> crate::ServiceResult<contextdb_service::CaptureAcceptance> {
        if request.event.kind == contextdb_core::EventKind::ToolCompleted
            && self.fail.swap(false, Ordering::SeqCst)
        {
            return Err(crate::ServiceError::new(
                crate::ErrorCode::Unavailable,
                "injected capture interruption",
                true,
            ));
        }
        self.owner.append_event_with_status(request)
    }
    fn read_original(
        &self,
        request: contextdb_service::ReadOriginalRequest,
    ) -> crate::ServiceResult<contextdb_service::CapturedOriginal> {
        self.owner.read_original(request)
    }
    fn resolve_capture_receipt(
        &self,
        context: &crate::AuthenticatedRequestContext,
        receipt: &contextdb_service::CaptureReceipt,
    ) -> crate::ServiceResult<()> {
        self.owner.resolve_capture_receipt(context, receipt)
    }
    fn producer_coverage(
        &self,
        context: &crate::AuthenticatedRequestContext,
        producer: contextdb_core::StreamId,
    ) -> crate::ServiceResult<contextdb_service::ProducerCoverage> {
        self.owner.producer_coverage(context, producer)
    }
}
impl PayloadPort for FlakyOwner {
    fn stage_payload(
        &self,
        request: contextdb_service::StagePayloadRequest,
    ) -> crate::ServiceResult<contextdb_service::PayloadReceipt> {
        self.owner.stage_payload(request)
    }
    fn read_original_span(
        &self,
        context: &crate::AuthenticatedRequestContext,
        span: &contextdb_core::OriginalSourceSpan,
    ) -> crate::ServiceResult<Vec<u8>> {
        self.owner.read_original_span(context, span)
    }
}

use contextdb_capture::{
    ArtifactObservation, CaptureHost, ExternalTool, ToolAction, ToolObservation, ToolOutcome,
    ToolOutcomeSlot, ToolReconciliation, ToolReplaySafety,
};
use contextdb_core::{ArtifactId, ContentDigest, ToolCallId};
use contextdb_service::{CapturePort, PayloadPort};
use serde::{Deserialize, Serialize};

use crate::{NativeService, capture::tests::request};

#[derive(Serialize, Deserialize)]
struct TargetRecord {
    digest: ContentDigest,
    bytes: Vec<u8>,
}

struct FileTarget {
    path: PathBuf,
    executions: AtomicUsize,
    crash: bool,
}

impl ExternalTool for FileTarget {
    fn replay_safety(&self) -> ToolReplaySafety {
        ToolReplaySafety::NoAutomaticReplay
    }
    fn execute(
        &self,
        _: &crate::AuthenticatedRequestContext,
        _: ToolCallId,
        action: &ToolAction,
    ) -> crate::ServiceResult<ToolObservation> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        let bytes = serde_json::to_vec(action).expect("action");
        let result = TargetRecord {
            digest: hash(&bytes),
            bytes: action.input.clone(),
        };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.path)
            .map_err(|_| crate::invalid("target already exists"))?;
        file.write_all(&serde_json::to_vec(&result).expect("target record"))
            .expect("write external effect");
        file.sync_all().expect("sync external effect");
        if self.crash {
            std::process::exit(86);
        }
        Ok(observation(result.bytes))
    }
    fn reconcile(
        &self,
        _: &crate::AuthenticatedRequestContext,
        _: ToolCallId,
        _: ContentDigest,
    ) -> crate::ServiceResult<ToolReconciliation> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let record: TargetRecord = serde_json::from_slice(&bytes)
                    .map_err(|_| crate::integrity("target result is incomplete"))?;
                Ok(ToolReconciliation::Observed {
                    action_digest: record.digest,
                    observation: observation(record.bytes),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ToolReconciliation::NotApplied {
                    current_target_version: None,
                })
            }
            Err(_) => Ok(ToolReconciliation::Unknown),
        }
    }
}

fn hash(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}
fn observation(bytes: Vec<u8>) -> ToolObservation {
    ToolObservation {
        outcome: ToolOutcome::Completed,
        bytes: Some(bytes),
        media_type: "application/octet-stream".into(),
        upstream_truncated: false,
    }
}
fn call_id() -> ToolCallId {
    ToolCallId::from_uuid(request(1, "").event.event_id.as_uuid()).expect("call")
}
fn slot() -> ToolOutcomeSlot {
    let value = request(2, "");
    ToolOutcomeSlot {
        event_id: value.event.event_id,
        producer_sequence: 2,
        recorded_at: value.event.recorded_at,
        idempotency_key: "tool-outcome".into(),
    }
}
fn action() -> ToolAction {
    ToolAction {
        operation: "create-fixture".into(),
        input: b"full external output\0\r\n".to_vec(),
        expected_target_version: Some("absent".into()),
    }
}

#[test]
fn tool_retry_preserves_action_pairing_and_does_not_repeat_external_effect() {
    let dir = tempfile::tempdir().expect("directory");
    let owner = Arc::new(
        NativeService::open(dir.path().join("native"), "capture-db", [7; 32]).expect("open"),
    );
    let host = CaptureHost::new(Arc::clone(&owner));
    let target = FileTarget {
        path: dir.path().join("external"),
        executions: AtomicUsize::new(0),
        crash: false,
    };
    let mut input = request(1, "");
    input.event.run_id = Some(contextdb_core::AgentRunId::new());
    input.event.task_id = Some(contextdb_core::TaskId::new());
    let first = host
        .run_tool(input.clone(), call_id(), &action(), slot(), &target)
        .expect("tool");
    let retry = host
        .run_tool(input.clone(), call_id(), &action(), slot(), &target)
        .expect("retry");
    assert_eq!(first.observed, retry.observed);
    assert_eq!(target.executions.load(Ordering::SeqCst), 1);
    let mut different = action();
    different.input = b"different action".to_vec();
    assert_eq!(
        host.run_tool(input.clone(), call_id(), &different, slot(), &target)
            .expect_err("changed action")
            .error
            .code,
        crate::ErrorCode::IdempotencyConflict
    );
    assert_eq!(target.executions.load(Ordering::SeqCst), 1);
    let mut changed_artifact = request(3, "");
    changed_artifact.event.run_id = input.event.run_id;
    changed_artifact.event.task_id = input.event.task_id;
    changed_artifact
        .event
        .parent_event_ids
        .insert(first.observed.expect("outcome receipt").event_id);
    host.capture_artifact(
        changed_artifact,
        ArtifactObservation {
            artifact_id: ArtifactId::new(),
            previous: None,
            bytes: Some(std::fs::read(&target.path).expect("observed file version")),
            media_type: "application/json".into(),
            rescan_after_gap: false,
        },
    )
    .expect("artifact linked to action in the same task trace");
    owner.verify_native(true).expect("action/outcome closure");
}

#[test]
fn failed_output_capture_retains_all_bytes_and_retries_without_execution() {
    let dir = tempfile::tempdir().expect("directory");
    let owner = Arc::new(
        NativeService::open(dir.path().join("native"), "capture-db", [7; 32]).expect("open"),
    );
    let host = CaptureHost::new(Arc::new(FlakyOwner {
        owner: Arc::clone(&owner),
        fail: std::sync::atomic::AtomicBool::new(true),
    }));
    let target = FileTarget {
        path: dir.path().join("external"),
        executions: AtomicUsize::new(0),
        crash: false,
    };
    let mut input = action();
    input.input = vec![b'x'; crate::CAPTURE_MAX_INLINE_BYTES + 1];
    let failed = host
        .run_tool(request(1, ""), call_id(), &input, slot(), &target)
        .expect_err("interrupted persistence");
    let pending = *failed.pending.expect("full output retained");
    assert_eq!(
        pending.observation.bytes.as_deref(),
        Some(input.input.as_slice())
    );
    let recovered = host.retry_tool_capture(pending).expect("capture retry");
    assert_eq!(target.executions.load(Ordering::SeqCst), 1);
    let receipt = recovered.observed.expect("durable outcome");
    let span = contextdb_core::OriginalSourceSpan {
        event_id: receipt.event_id,
        payload_digest: hash(&input.input),
        start: 0,
        end: u64::try_from(input.input.len()).expect("length"),
        span_digest: hash(&input.input),
    };
    assert_eq!(
        owner
            .read_original_span(&request(1, "").context, &span)
            .expect("full outcome"),
        input.input
    );
    owner
        .verify_native(true)
        .expect("complete staged payload closure");
}

#[test]
fn artifact_versions_preserve_large_originals_and_rescan_gaps() {
    let dir = tempfile::tempdir().expect("directory");
    let owner = Arc::new(NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open"));
    let host = CaptureHost::new(Arc::clone(&owner));
    let id = ArtifactId::new();
    let original = host
        .capture_artifact(
            request(1, ""),
            ArtifactObservation {
                artifact_id: id,
                previous: None,
                bytes: Some(b"before".to_vec()),
                media_type: "text/plain".into(),
                rescan_after_gap: false,
            },
        )
        .expect("first");
    let bytes = vec![42; crate::CAPTURE_MAX_INLINE_BYTES + 37];
    let updated = host
        .capture_artifact(
            request(2, ""),
            ArtifactObservation {
                artifact_id: id,
                previous: Some(original.receipt.clone()),
                bytes: Some(bytes.clone()),
                media_type: "application/octet-stream".into(),
                rescan_after_gap: true,
            },
        )
        .expect("rescan");
    let source = contextdb_core::OriginalSourceSpan {
        event_id: updated.receipt.event_id,
        payload_digest: hash(&bytes),
        start: 0,
        end: u64::try_from(bytes.len()).expect("length"),
        span_digest: hash(&bytes),
    };
    assert_eq!(
        owner
            .read_original_span(&request(1, "").context, &source)
            .expect("full bytes"),
        bytes
    );
    let deleted = host
        .capture_artifact(
            request(3, ""),
            ArtifactObservation {
                artifact_id: id,
                previous: Some(updated.receipt),
                bytes: None,
                media_type: "text/plain".into(),
                rescan_after_gap: false,
            },
        )
        .expect("deletion");
    host.capture_artifact(
        request(4, ""),
        ArtifactObservation {
            artifact_id: id,
            previous: Some(deleted.receipt),
            bytes: Some(b"recreated".to_vec()),
            media_type: "text/plain".into(),
            rescan_after_gap: false,
        },
    )
    .expect("recreated source");
    owner
        .resolve_capture_receipt(&request(1, "").context, &original.receipt)
        .expect("original history remains");
    owner.verify_native(true).expect("artifact closure");
}

#[test]
fn tool_effect_crash_child() {
    let Ok(path) = std::env::var("CONTEXTDB_TOOL_CRASH_PATH") else {
        return;
    };
    let path = PathBuf::from(path);
    let owner = Arc::new(
        NativeService::open(path.join("native"), "capture-db", [7; 32]).expect("child open"),
    );
    let host = CaptureHost::new(owner);
    let target = FileTarget {
        path: path.join("external"),
        executions: AtomicUsize::new(0),
        crash: true,
    };
    host.run_tool(request(1, ""), call_id(), &action(), slot(), &target)
        .expect("child tool");
    panic!("external crash injection did not run");
}

#[test]
fn crash_after_real_file_effect_recovers_through_target_reconciliation() {
    let dir = tempfile::tempdir().expect("directory");
    let status = Command::new(std::env::current_exe().expect("binary"))
        .args([
            "--exact",
            "adapter_tests::tool_effect_crash_child",
            "--nocapture",
        ])
        .env("CONTEXTDB_TOOL_CRASH_PATH", dir.path())
        .status()
        .expect("subprocess");
    assert_eq!(status.code(), Some(86));
    let external_before = std::fs::read(dir.path().join("external")).expect("effect survived");
    let owner = Arc::new(
        NativeService::open(dir.path().join("native"), "capture-db", [7; 32]).expect("recover"),
    );
    let host = CaptureHost::new(Arc::clone(&owner));
    let target = FileTarget {
        path: dir.path().join("external"),
        executions: AtomicUsize::new(0),
        crash: false,
    };
    let recovered = host
        .run_tool(request(1, ""), call_id(), &action(), slot(), &target)
        .expect("reconcile");
    assert_eq!(recovered.outcome, ToolOutcome::Completed);
    assert!(recovered.observed.is_some());
    assert_eq!(target.executions.load(Ordering::SeqCst), 0);
    assert_eq!(
        std::fs::read(&target.path).expect("external target"),
        external_before
    );
    owner.verify_native(true).expect("recovered trace");
}
