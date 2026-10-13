//! Complete native interval and ordered doc-control commitment before fresh data.
//! Private denied controls authenticate the prefix; raw/vector access needs ACL.

use super::super::super::segments::crypto::metered_json_len;
use super::super::*;
use super::view::VerifiedRoutedQueryView;
use crate::capture::CaptureWork;
use contextdb_storage::ScanPageRequest;
use std::mem::size_of;

pub(super) struct RoutedFreshInput {
    pub(super) complete: bool,
    pub(super) has_work: bool,
    pub(super) has_vectors: bool,
    pub(super) omissions: bool,
    pub(super) work: u64,
    pub(super) documents: Vec<(DenseDocument, IndexedOriginal)>,
}

impl RoutedFreshInput {
    fn incomplete(work: usize) -> Self {
        Self {
            complete: false,
            has_work: true,
            has_vectors: false,
            omissions: false,
            work: work as u64,
            documents: Vec::new(),
        }
    }
}

pub(super) fn admit_routed_fresh<S: ReadSnapshot>(
    native: &NativeService,
    snapshot: &S,
    context: &AuthenticatedRequestContext,
    view: &VerifiedRoutedQueryView,
    max_work: usize,
    parent: &mut QueryBudget,
) -> ServiceResult<RoutedFreshInput> {
    if !(1..=128).contains(&max_work) {
        return Err(crate::invalid("routed fresh work bound invalid"));
    }
    native.check_routed_query_view(context, view, parent)?;
    let covered = &view.router().manifest.covered;
    let latest = view.current_dense();
    if covered == latest {
        return Ok(RoutedFreshInput {
            complete: true,
            has_work: false,
            has_vectors: false,
            omissions: false,
            work: 0,
            documents: Vec::new(),
        });
    }
    let start = native.verify_prefix_segment_capture_boundary(
        snapshot,
        view.workspace(),
        view.ending(),
        parent,
    )?;
    let (accepted, manifest) = native.prefix_dense_target_binding(
        snapshot,
        view.workspace(),
        view.current_dense_ref(),
        parent,
    )?;
    if manifest != *latest
        || accepted.generation != view.generation().number
        || accepted.authorization_epoch != view.generation().authorization_epoch
        || covered.through >= latest.through
        || start.reference().global_commit >= view.current_dense_ref().global_commit
    {
        return Err(integrity("routed fresh anchor/current dense point differs"));
    }
    parent
        .charge(1, max_work as u64 * size_of::<CaptureWork>() as u64 + 4096)
        .map_err(budget_error)?;
    let mut work = Vec::with_capacity(max_work);
    let mut previous_commit = start.reference().global_commit;
    let mut previous_digest = start.reference().event_digest.clone();
    let mut previous_workspace = start.reference().work.workspace_commit;
    let mut after_key = previous_commit.to_be_bytes().to_vec();
    'journal: loop {
        native.check_routed_query_view(context, view, parent)?;
        let page = crate::budgeted::metadata(snapshot, parent, |r| {
            r.scan_prefix_page(
                &native.keyspaces.events,
                ScanPageRequest {
                    prefix: b"",
                    start_after: Some(&after_key),
                    max_entries: 32,
                    max_bytes: crate::MAX_JSON_BYTES + KEY_BYTES as usize + 256,
                },
            )
            .map_err(storage_error)
        })?;
        for row in page.entries {
            if row.value.len() > crate::MAX_JSON_BYTES {
                return Err(integrity("routed fresh native row exceeds bound"));
            }
            parent
                .charge(
                    row.value.len() as u64 * 8 + 1,
                    row.value.len() as u64 * 16 + 8192,
                )
                .map_err(budget_error)?;
            let event: crate::StoredEvent =
                decode(&row.value, "routed fresh accepted native interval")?;
            if event.schema_version != crate::SCHEMA_VERSION
                || row.key != event.global_commit.to_be_bytes()
                || previous_commit.checked_add(1) != Some(event.global_commit)
                || event.global_commit > view.current_dense_ref().global_commit
                || event.previous_event_digest.as_ref() != Some(&previous_digest)
                || event.event_digest != crate::event_digest(&event)?
                || encode(&event)? != row.value
                || (event.operation == "capture") != event.accepted_original.is_some()
            {
                return Err(integrity(
                    "routed fresh native interval has a changed or missing frame",
                ));
            }
            previous_commit = event.global_commit;
            previous_digest = event.event_digest;
            if event.workspace_digest == view.workspace() {
                if event.workspace_commit <= previous_workspace {
                    return Err(integrity("routed fresh workspace history is not ordered"));
                }
                previous_workspace = event.workspace_commit;
                if let Some(expected) = event.accepted_original {
                    if expected.workspace_commit != event.workspace_commit
                        || expected.workspace_commit <= covered.through
                    {
                        return Err(integrity(
                            "routed fresh actual ending capture is not the complete covered boundary",
                        ));
                    }
                    if expected.workspace_commit <= latest.through {
                        if work.len() == max_work {
                            // No outcomes or documents have been processed. Nothing
                            // from this partial interval can become fresh authority.
                            native.check_routed_query_view(context, view, parent)?;
                            return Ok(RoutedFreshInput::incomplete(work.len()));
                        }
                        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
                        let actual: CaptureWork = native
                            .graph_read(
                                snapshot,
                                &native.keyspaces.continuous,
                                &crate::capture::work_key(
                                    view.workspace(),
                                    expected.workspace_commit,
                                ),
                                parent,
                            )?
                            .ok_or_else(|| {
                                integrity("routed fresh accepted outbox work is absent")
                            })?;
                        if actual != expected {
                            return Err(integrity(
                                "routed fresh exact accepted outbox work differs",
                            ));
                        }
                        work.push(expected);
                    }
                }
            }
            if previous_commit == view.current_dense_ref().global_commit {
                break 'journal;
            }
        }
        let next = page.continuation.ok_or_else(|| {
            integrity("routed fresh native history ends before accepted dense event")
        })?;
        if next <= after_key {
            return Err(integrity("routed fresh native interval made no progress"));
        }
        after_key = next;
    }
    if previous_digest != view.current_dense_ref().event_digest {
        return Err(integrity(
            "routed fresh interval ends at another native dense acceptance",
        ));
    }
    if work.is_empty() {
        return Err(integrity(
            "routed advanced dense state has no actual accepted fresh work",
        ));
    }
    native.check_routed_query_view(context, view, parent)?;
    let prefix_bytes = metered_json_len(covered, parent, ROW_BYTES)?;
    parent
        .charge(
            prefix_bytes as u64 + 1,
            prefix_bytes as u64 * 8 + 8192 + work.len() as u64 * size_of::<DenseDocument>() as u64,
        )
        .map_err(budget_error)?;
    let mut reproduced = covered.clone();
    let mut controls = Vec::with_capacity(work.len());
    // A doc token omits generation/workspace. Native interval completeness plus
    // a valid old token is insufficient: reproduce the CURRENT accepted chain
    // from every tagged doc control, including sources denied for disclosure.
    for expected in &work {
        native.check_routed_query_view(context, view, parent)?;
        native.verified_capture_boundary_metadata(snapshot, view.workspace(), expected, parent)?;
        let (capture, recovery) =
            native.capture_recovery_metadata(snapshot, expected.event_id, parent)?;
        if recovery.is_none()
            || native.capture_work_for_receipt_with_budget(snapshot, &capture, parent)? != *expected
        {
            return Err(integrity("routed fresh capture/recovery control differs"));
        }
        if native.source_prepared_at(
            snapshot,
            view.workspace(),
            expected.event_id,
            view.generation().removal_through,
            parent,
        )? {
            continue;
        }
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let document: DenseDocument = native
            .graph_read(
                snapshot,
                &native.keyspaces.continuous,
                &document_key(
                    view.workspace(),
                    view.generation().number,
                    expected.event_id,
                ),
                parent,
            )?
            .ok_or_else(|| integrity("routed complete fresh doc control absent"))?;
        let size = metered_json_len(&document, parent, ROW_BYTES)?;
        parent
            .charge(size as u64 + 1, size as u64 * 8 + 8192)
            .map_err(budget_error)?;
        native.check_dense_document_token(&document)?;
        if document.source.event_id != expected.event_id
            || document.event_digest != expected.event_digest
            || document.commit != expected.workspace_commit
            || document.source.payload_digest != capture.payload_digest
            || document.profile_digest != latest.profile_digest
            || document.spans.len() > 64
            || (document.omission.is_some() && !document.spans.is_empty())
            || (document.omission.is_none() && document.spans.is_empty())
            || document.spans.iter().any(|span| {
                span.span.event_id != document.source.event_id
                    || Some(span.span.payload_digest) != document.source.payload_digest
                    || span.span.start >= span.span.end
                    || document
                        .source
                        .byte_length
                        .is_none_or(|n| span.span.end > n)
            })
        {
            return Err(integrity(
                "routed fresh doc control differs from actual capture/whole plan",
            ));
        }
        let bytes = metered_json_len(
            &(
                "contextdb.native-source-embedding-chain.v1",
                reproduced.commitment,
                &document,
            ),
            parent,
            ROW_BYTES * 2,
        )?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 4 + 512)
            .map_err(budget_error)?;
        reproduced.accept(&document)?;
        controls.push(document);
    }
    reproduced.through = latest.through;
    if reproduced != *latest {
        return Err(integrity(
            "routed complete fresh doc commitment differs from accepted current dense manifest",
        ));
    }
    // No fresh raw metadata, body, vector or model materialization precedes the
    // exact complete commitment equality. Controls never enter the frontier.
    native.check_routed_query_view(context, view, parent)?;
    parent
        .charge(
            1,
            controls.len() as u64 * size_of::<(DenseDocument, IndexedOriginal)>() as u64 + 4096,
        )
        .map_err(budget_error)?;
    let mut documents = Vec::with_capacity(controls.len());
    let mut omissions = false;
    let mut has_vectors = false;
    for document in controls {
        native.check_routed_query_view(context, view, parent)?;
        let event_id = document.source.event_id;
        let current = native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let permission = native
            .authorized_capture_policy_with_budget(&current, context, event_id, parent)
            .and_then(|_| {
                native.authorize_derived_custody_with_budget(&current, context, event_id, parent)
            });
        match permission {
            Ok(_) => {}
            Err(error) if error.code == ErrorCode::PermissionDenied => continue,
            Err(error) if error.code == ErrorCode::NotFound => {
                return Err(integrity(
                    "routed accepted fresh source lost current authorization controls",
                ));
            }
            Err(error) => return Err(error),
        }
        native.check_routed_query_view(context, view, parent)?;
        let current_raw = native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        native.authorized_capture_policy_with_budget(&current_raw, context, event_id, parent)?;
        native.authorize_derived_custody_with_budget(&current_raw, context, event_id, parent)?;
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let bytes = crate::budgeted::read_value(
            snapshot,
            &native.keyspaces.continuous,
            &doc_key(view.workspace(), view.generation().number, event_id),
            4 * 1024 * 1024,
            parent,
        )?
        .ok_or_else(|| integrity("routed permitted actual raw metadata absent"))?;
        parent
            .charge(bytes.len() as u64 + 1, bytes.len() as u64 * 16 + 8192)
            .map_err(budget_error)?;
        let original: IndexedOriginal = decode(&bytes, "routed actual fresh raw metadata")?;
        native.verify_projected_causal_metadata(snapshot, view.workspace(), &original, parent)?;
        if document.source != original.source
            || document.event_digest != original.event_digest
            || document.commit != original.commit
            || document.policy_domain != original.policy_domain
        {
            return Err(integrity("routed fresh source/version/whole plan differs"));
        }
        let policies =
            native.stored_custody_policies_with_budget(&current_raw, event_id, parent)?;
        let bytes = metered_json_len(&policies, parent, ROW_BYTES)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 8 + 4096)
            .map_err(budget_error)?;
        if canonical_digest(&policies)? != document.policy_domain {
            return Err(integrity("routed fresh complete compound policy differs"));
        }
        native.check_routed_query_view(context, view, parent)?;
        omissions |= matches!(
            document.omission,
            Some(DenseOmission::Unavailable | DenseOmission::NonText | DenseOmission::TooLarge)
        ) || document.source.upstream_truncated
            || document.source.coverage != contextdb_core::EventCoverage::CompleteObservation;
        has_vectors |= !document.spans.is_empty();
        documents.push((document, original));
    }
    native.check_routed_query_view(context, view, parent)?;
    Ok(RoutedFreshInput {
        complete: true,
        has_work: has_vectors,
        has_vectors,
        omissions,
        work: work.len() as u64,
        documents,
    })
}
