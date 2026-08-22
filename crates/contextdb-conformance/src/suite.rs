use contextdb_service::{
    ErrorCode, ExplainRecallRequest, ExportRequest, ImportRequest, ObserveResponse, RecallResponse,
    VerifyRequest,
};

use crate::adapters::ConformanceAdapter;
use crate::{
    CanonicalOperation, CanonicalOutcome, CanonicalResponse, Capability, ConformanceFixture,
    ConformanceReport, ConformanceResult, InterfaceKind, Support,
};

/// Runs the common deterministic semantic suite against one real interface
/// adapter. The adapter must start with an empty logical database.
pub async fn run_conformance_suite(
    adapter: &mut dyn ConformanceAdapter,
    fixture: &ConformanceFixture,
) -> ConformanceResult<ConformanceReport> {
    let mut report = ConformanceReport::new(adapter.manifest());
    let unclassified = report.manifest.unclassified();
    report.push(
        "manifest.complete",
        unclassified.is_empty(),
        "every v1 capability is explicitly classified",
        Some(&unclassified),
    );

    let first = invoke(
        adapter,
        CanonicalOperation::Observe(fixture.visible_a.clone()),
    )
    .await?;
    let first_receipt = observe_response(&first);
    report.push(
        "observe.first_commit",
        first_receipt.is_some_and(|receipt| {
            receipt.commit_seq == fixture.initial_commit_seq.saturating_add(1) && !receipt.replayed
        }),
        "first valid observation commits exactly once",
        first_receipt,
    );

    let replay = invoke(
        adapter,
        CanonicalOperation::Observe(fixture.visible_a.clone()),
    )
    .await?;
    let replay_receipt = observe_response(&replay);
    let replay_ok = first_receipt
        .zip(replay_receipt)
        .is_some_and(|(first, replay)| {
            replay.replayed
                && replay.commit_seq == first.commit_seq
                && replay.request_digest == first.request_digest
                && replay.watermarks == first.watermarks
        });
    report.push(
        "idempotency.exact_replay",
        replay_ok,
        "same scoped key and digest returns the original receipt without a commit",
        replay_receipt,
    );

    let conflict = invoke(
        adapter,
        CanonicalOperation::Observe(fixture.idempotency_conflict()),
    )
    .await?;
    report.push(
        "idempotency.changed_digest_conflict",
        error_code(&conflict) == Some(ErrorCode::IdempotencyConflict),
        "same scoped key with changed canonical input is rejected",
        Some(&conflict),
    );

    let second = invoke(
        adapter,
        CanonicalOperation::Observe(fixture.visible_b.clone()),
    )
    .await?;
    report.push(
        "observe.ordered_commits",
        observe_response(&second).is_some_and(|receipt| {
            receipt.commit_seq == fixture.initial_commit_seq.saturating_add(2)
        }),
        "successful writes advance the ordered journal by one",
        Some(&second),
    );

    let baseline = invoke(adapter, CanonicalOperation::Recall(fixture.recall(10))).await?;
    let baseline_page = recall_response(&baseline);
    report.push(
        "recall.visible_baseline",
        baseline_page.is_some_and(|page| {
            let ids = page
                .hits
                .iter()
                .map(|hit| hit.id.clone())
                .collect::<Vec<_>>();
            page.hits.len() == 2
                && page.trace.authorized_candidates == 2
                && fixture
                    .expected_visible_ids
                    .iter()
                    .all(|expected| ids.contains(expected))
                && !ids.contains(&fixture.forbidden_semantic_id)
        }),
        "both authorized memories are selected before the forbidden write",
        baseline_page,
    );

    let forbidden = invoke(
        adapter,
        CanonicalOperation::Observe(fixture.forbidden.clone()),
    )
    .await?;
    let forbidden_commit = observe_response(&forbidden).map(|receipt| receipt.commit_seq);
    let fixed_mcp_boundary_denied = adapter.interface() == InterfaceKind::Mcp
        && error_code(&forbidden) == Some(ErrorCode::Unauthorized);
    report.push(
        "observe.forbidden_stored",
        forbidden_commit
            .is_some_and(|commit| commit == fixture.initial_commit_seq.saturating_add(3))
            || fixed_mcp_boundary_denied,
        "a separate principal can store policy-labelled memory, or a fixed MCP session rejects that cross-principal write at its host boundary",
        Some(&forbidden),
    );

    let after_forbidden = invoke(adapter, CanonicalOperation::Recall(fixture.recall(10))).await?;
    let after_forbidden_page = recall_response(&after_forbidden);
    let forbidden_non_influence =
        baseline_page
            .zip(after_forbidden_page)
            .is_some_and(|(before, after)| {
                before.hits == after.hits
                    && before.trace.authorized_candidates == after.trace.authorized_candidates
                    && before.trace.selected_ids == after.trace.selected_ids
                    && !after
                        .hits
                        .iter()
                        .any(|hit| hit.id == fixture.forbidden_semantic_id)
            });
    report.push(
        "privacy.forbidden_non_influence",
        forbidden_non_influence,
        "unauthorized content changes neither candidates, scores, selection, nor trace counts",
        after_forbidden_page,
    );

    let page_request = fixture.recall(1);
    let first_page_outcome =
        invoke(adapter, CanonicalOperation::Recall(page_request.clone())).await?;
    let first_page = recall_response(&first_page_outcome).cloned();
    report.push(
        "continuation.issued",
        first_page
            .as_ref()
            .is_some_and(|page| page.hits.len() == 1 && page.continuation.is_some()),
        "a bounded first page issues an opaque continuation",
        first_page.as_ref(),
    );

    let late = invoke(
        adapter,
        CanonicalOperation::Observe(fixture.late_visible.clone()),
    )
    .await?;
    report.push(
        "continuation.concurrent_write",
        observe_response(&late).is_some_and(|receipt| {
            let expected_offset = if forbidden_commit.is_some() { 4 } else { 3 };
            receipt.commit_seq == fixture.initial_commit_seq.saturating_add(expected_offset)
        }),
        "a later write commits after continuation issuance",
        Some(&late),
    );

    if let Some(first_page) = first_page.as_ref() {
        let token = first_page.continuation.clone().unwrap_or_default();
        let mut continued_request = page_request.clone();
        continued_request.continuation = Some(token.clone());
        let continued = invoke(
            adapter,
            CanonicalOperation::Recall(continued_request.clone()),
        )
        .await?;
        let continued_page = recall_response(&continued);
        let snapshot_bound = continued_page.is_some_and(|page| {
            page.trace.snapshot_seq == first_page.trace.snapshot_seq
                && !page
                    .hits
                    .iter()
                    .any(|hit| hit.id == fixture.late_visible.observation_id)
        });
        report.push(
            "continuation.snapshot_bound",
            snapshot_bound,
            "continuation remains at its original snapshot after a later commit",
            continued_page,
        );

        let mut changed_filter = continued_request.clone();
        changed_filter.query = "different filter".to_owned();
        let changed = invoke(adapter, CanonicalOperation::Recall(changed_filter)).await?;
        report.push(
            "continuation.filter_bound",
            error_code(&changed) == Some(ErrorCode::InvalidContinuation),
            "continuation cannot be replayed with a changed query/filter",
            Some(&changed),
        );

        let mut wrong_person = continued_request;
        wrong_person.context = fixture.other_principal.clone();
        let wrong = invoke(adapter, CanonicalOperation::Recall(wrong_person)).await?;
        report.push(
            "continuation.principal_bound",
            matches!(
                error_code(&wrong),
                Some(ErrorCode::InvalidContinuation | ErrorCode::Unauthorized)
            ),
            "continuation cannot be reused by another principal",
            Some(&wrong),
        );

        let explain = invoke(
            adapter,
            CanonicalOperation::ExplainRecall(ExplainRecallRequest {
                context: fixture.caller.clone(),
                trace: first_page.trace.clone(),
            }),
        )
        .await?;
        report.push(
            "trace.authenticated",
            matches!(
                &explain,
                Ok(CanonicalResponse::ExplainRecall(trace)) if trace == &first_page.trace
            ),
            "authorized caller can validate its exact privacy-safe trace",
            Some(&explain),
        );

        let wrong_explain = invoke(
            adapter,
            CanonicalOperation::ExplainRecall(ExplainRecallRequest {
                context: fixture.other_principal.clone(),
                trace: first_page.trace.clone(),
            }),
        )
        .await?;
        report.push(
            "trace.principal_bound",
            matches!(
                error_code(&wrong_explain),
                Some(ErrorCode::PermissionDenied | ErrorCode::Unauthorized)
            ),
            "another principal cannot validate or enumerate a trace",
            Some(&wrong_explain),
        );

        let mut forged = token;
        if let Some(last) = forged.pop() {
            forged.push(if last == 'a' { 'b' } else { 'a' });
        }
        let mut forged_request = page_request.clone();
        forged_request.continuation = Some(forged);
        let forged_outcome = invoke(adapter, CanonicalOperation::Recall(forged_request)).await?;
        report.push(
            "continuation.forgery_rejected",
            error_code(&forged_outcome) == Some(ErrorCode::InvalidContinuation),
            "modified opaque continuation fails authentication",
            Some(&forged_outcome),
        );
    } else {
        for id in [
            "continuation.snapshot_bound",
            "continuation.filter_bound",
            "continuation.principal_bound",
            "trace.authenticated",
            "trace.principal_bound",
            "continuation.forgery_rejected",
        ] {
            report.not_exercised(id, "first page did not produce a continuation");
        }
    }

    let mut unknown_request = fixture.recall(10);
    unknown_request.query = "unfindable-token-5e64b2".to_owned();
    let unknown = invoke(adapter, CanonicalOperation::Recall(unknown_request)).await?;
    report.push(
        "recall.unknown_is_empty",
        recall_response(&unknown).is_some_and(|page| {
            page.hits.is_empty()
                && page.trace.selected_ids.is_empty()
                && page.continuation.is_none()
        }),
        "unknown is represented as an empty authorized result, not invented memory",
        Some(&unknown),
    );

    let omission = invoke(
        adapter,
        CanonicalOperation::Observe(fixture.policy_omission()),
    )
    .await?;
    report.push(
        "policy.missing_owner_rejected",
        error_code(&omission) == Some(ErrorCode::InvalidArgument),
        "publishable memory cannot omit ownership policy",
        Some(&omission),
    );

    if matches!(
        report
            .manifest
            .capabilities
            .get(&Capability::PortableArchive),
        Some(Support::Exercised)
    ) {
        let exported = invoke(
            adapter,
            CanonicalOperation::Export(ExportRequest {
                context: fixture.administrator.clone(),
            }),
        )
        .await?;
        let verified = invoke(
            adapter,
            CanonicalOperation::Verify(VerifyRequest {
                context: fixture.administrator.clone(),
                deep: true,
            }),
        )
        .await?;
        let archive_ok = match (&exported, &verified) {
            (Ok(CanonicalResponse::Export(archive)), Ok(CanonicalResponse::Verify(verify))) => {
                verify.valid
                    && archive.commit_seq == verify.commit_seq
                    && verify.archive_digest.as_deref() == Some(archive.digest.as_str())
                    && blake3::hash(&archive.bytes).to_hex().to_string() == archive.digest
            }
            _ => false,
        };
        report.push(
            "archive.canonical_deep_verify",
            archive_ok,
            "archive bytes, digest, head, and deep replay agree",
            Some(&(exported, verified)),
        );
    } else {
        report.push::<()>(
            "archive.canonical_deep_verify",
            true,
            "database-global archives are outside this workspace interface",
            None,
        );
    }

    report.finalize();
    Ok(report)
}

/// Proves canonical archive import/export equivalence between an initialized
/// source adapter and a separate empty target adapter.
pub async fn run_archive_round_trip(
    source: &mut dyn ConformanceAdapter,
    target: &mut dyn ConformanceAdapter,
    administrator: &contextdb_service::RequestContext,
) -> ConformanceResult<bool> {
    let exported = invoke(
        source,
        CanonicalOperation::Export(ExportRequest {
            context: administrator.clone(),
        }),
    )
    .await?;
    let Ok(CanonicalResponse::Export(archive)) = exported else {
        return Ok(false);
    };
    let imported = invoke(
        target,
        CanonicalOperation::Import(ImportRequest {
            context: administrator.clone(),
            format: archive.format.clone(),
            bytes: archive.bytes.clone(),
            digest: archive.digest.clone(),
        }),
    )
    .await?;
    let Ok(CanonicalResponse::Import(receipt)) = imported else {
        return Ok(false);
    };
    let replayed = invoke(
        target,
        CanonicalOperation::Export(ExportRequest {
            context: administrator.clone(),
        }),
    )
    .await?;
    Ok(matches!(
        replayed,
        Ok(CanonicalResponse::Export(replayed))
            if receipt.commit_seq == archive.commit_seq
                && replayed.bytes == archive.bytes
                && replayed.digest == archive.digest
                && replayed.format == archive.format
    ))
}

async fn invoke(
    adapter: &mut dyn ConformanceAdapter,
    operation: CanonicalOperation,
) -> ConformanceResult<CanonicalOutcome> {
    adapter.invoke(operation).await
}

fn observe_response(outcome: &CanonicalOutcome) -> Option<&ObserveResponse> {
    match outcome {
        Ok(CanonicalResponse::Observe(response)) => Some(response),
        _ => None,
    }
}

fn recall_response(outcome: &CanonicalOutcome) -> Option<&RecallResponse> {
    match outcome {
        Ok(CanonicalResponse::Recall(response)) => Some(response),
        _ => None,
    }
}

fn error_code(outcome: &CanonicalOutcome) -> Option<ErrorCode> {
    outcome.as_ref().err().map(|error| error.code)
}
