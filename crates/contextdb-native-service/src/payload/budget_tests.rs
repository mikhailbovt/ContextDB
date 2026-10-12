//! Parent-budget checks for the ranges used by native ranked discovery.

use std::time::Duration;

use contextdb_recall::{QueryBudget, QueryCancellation};
use contextdb_service::CapturePort;

use super::*;

fn budget(bytes: u64) -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        bytes,
        Duration::from_secs(30),
        QueryCancellation::default(),
    )
}

#[test]
fn maintenance_and_authorized_ranges_pay_for_authenticated_chunks_and_receipt_reads() {
    let directory = tempfile::tempdir().expect("native directory");
    let owner = NativeService::open(directory.path(), "range-budget", [7; 32]).expect("owner");
    let mut input = crate::capture::tests::request(1, "staged fixture");
    let bytes = (0..CHUNK_BYTES * 3)
        .map(|index| u8::try_from(index % 251).expect("byte"))
        .collect::<Vec<_>>();
    let staged = owner
        .stage_payload(StagePayloadRequest {
            context: input.context.clone(),
            idempotency_key: "ranked-range-budget".into(),
            block_id: ContentBlockId::new(),
            bytes: bytes.clone(),
        })
        .expect("staged original");
    input.event.payload = EventPayload::Staged {
        reference: staged.reference,
        media_type: "application/octet-stream".into(),
    };
    let accepted = owner
        .append_event(input.clone())
        .expect("accepted original");
    let snapshot = owner
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let start = (CHUNK_BYTES - 3) as u64;
    let end = (CHUNK_BYTES + 4) as u64;
    let expected = &bytes[CHUNK_BYTES - 3..CHUNK_BYTES + 4];

    let mut allowance = budget(16 * 1024 * 1024);
    let before = allowance.remaining_bytes();
    assert_eq!(
        owner
            .original_range_for_custody_with_budget(
                &snapshot,
                &input.event,
                start,
                end,
                &mut allowance,
            )
            .expect("maintenance range"),
        expected
    );
    assert!(before - allowance.remaining_bytes() >= (2 * CHUNK_BYTES + expected.len()) as u64);

    let mut allowance = budget(16 * 1024 * 1024);
    assert_eq!(
        owner
            .original_range_with_budget(
                &snapshot,
                &input.context,
                &input.event,
                start,
                end,
                &mut allowance,
            )
            .expect("authorized range"),
        expected
    );
    assert_eq!(
        owner
            .original_range_for_custody_with_budget(
                &snapshot,
                &input.event,
                start,
                end,
                &mut budget(64 * 1024),
            )
            .expect_err("seven requested bytes still require full storage chunks")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(
        owner
            .original_range_with_budget(
                &snapshot,
                &input.context,
                &input.event,
                start,
                end,
                &mut budget(64 * 1024),
            )
            .expect_err("context-bound range uses the same storage accounting")
            .code,
        ErrorCode::BudgetExhausted
    );

    let mut allowance = budget(16 * 1024 * 1024);
    let before = allowance.remaining_bytes();
    assert_eq!(
        owner
            .capture_work_for_receipt_with_budget(&snapshot, &accepted, &mut allowance,)
            .expect("budgeted accepted work"),
        owner
            .capture_work_for_receipt(&snapshot, &accepted,)
            .expect("accepted work")
    );
    assert!(
        allowance.remaining_bytes() < before,
        "receipt metadata is not free"
    );
    assert_eq!(
        owner
            .capture_work_for_receipt_with_budget(&snapshot, &accepted, &mut budget(0),)
            .expect_err("receipt metadata requires parent byte allowance")
            .code,
        ErrorCode::BudgetExhausted
    );

    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(
        1_000_000,
        16 * 1024 * 1024,
        Duration::from_secs(30),
        cancellation,
    );
    assert!(
        owner
            .original_range_for_custody_with_budget(
                &snapshot,
                &input.event,
                start,
                end,
                &mut cancelled,
            )
            .is_err()
    );
    owner
        .verify_native(true)
        .expect("no partial publication from read failures");
}
