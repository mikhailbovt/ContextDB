//! A real custody permission change must not change a frozen source's row omission.

use super::*;
use contextdb_core::{EventKind, ScopeId};
use uuid::Uuid;

#[test]
fn row_limit_reconstruction_is_independent_of_custody_label_order_and_revocation() {
    let directory = tempfile::tempdir().expect("native directory");
    let native =
        NativeService::open(directory.path(), "bm25-routing-bound", [17; 32]).expect("native");
    let mut parent =
        crate::capture::tests::request(1, "independent parent with broader scope labels");
    parent
        .event
        .scope_ids
        .extend((5..9).map(|id| ScopeId::from_uuid(Uuid::from_u128(id)).expect("scope")));
    parent.context.request.scopes = parent
        .event
        .scope_ids
        .iter()
        .map(ToString::to_string)
        .collect();
    native
        .append_event(parent.clone())
        .expect("accepted five-scope parent");

    // With one parent, one scoped routing seed fits these TF/DF rows, while
    // five scopes exceed the fixed per-source publication ceiling by one row.
    let term_count = (MAX_PROJECTION_ROWS - 8 - 5) / 2 + 1;
    assert!(term_count <= MAX_INDEX_TERMS);
    assert!(8 + 2 * term_count < MAX_PROJECTION_ROWS);
    assert!(8 + 2 * term_count + 5 > MAX_PROJECTION_ROWS);
    let text = (0..term_count)
        .map(|index| format!("token{index:05}"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut child = crate::capture::tests::request(2, &text);
    child.context.request.scopes = parent.context.request.scopes.clone();
    child.event.parent_event_ids.insert(parent.event.event_id);
    child.event.kind = EventKind::MessageEdited;
    child.event.supersedes_event_id = Some(parent.event.event_id);
    let receipt = native
        .append_event(child.clone())
        .expect("accepted original with one-scope direct label");
    native
        .maintain_custody(&child.context, 64, &mut allowance(128 * 1024 * 1024))
        .expect("current custody");
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before snapshot");
    let before = native
        .stored_custody_policies_with_budget(
            &snapshot,
            child.event.event_id,
            &mut allowance(128 * 1024 * 1024),
        )
        .expect("actual inherited labels");
    assert!(before.iter().any(|policy| policy.scopes.len() == 1));
    assert!(before.iter().any(|policy| policy.scopes.len() == 5));
    let frozen_domain = canonical_digest(&before).expect("frozen domain");
    let original = native
        .load_captured_original_with_budget(
            &snapshot,
            child.event.event_id,
            &mut allowance(128 * 1024 * 1024),
        )
        .expect("full accepted source");
    let count = routing_scope_count(&before).expect("intrinsic bound");
    assert_eq!(count, 5);
    let first = native
        .build_raw_bm25_documents(
            &snapshot,
            &original.event,
            receipt.workspace_commit,
            receipt.event_digest,
            &frozen_domain,
            count,
            &mut allowance(128 * 1024 * 1024),
        )
        .expect("before reconstruction");
    assert_eq!(first.1.omission, Some(Bm25Omission::RowLimit));
    assert_eq!(first.1.token_count, 0);
    assert!(first.1.term_frequencies.is_empty());
    assert!(first.0.lexical_complete);
    assert_eq!(first.0.first_terms.len(), term_count);
    drop(snapshot);

    native
        .revoke_original(
            &child.context,
            parent.event.event_id,
            "revoke-bm25-parent",
            &mut allowance(128 * 1024 * 1024),
        )
        .expect("actual permission change");
    native
        .maintain_custody(&child.context, 64, &mut allowance(128 * 1024 * 1024))
        .expect("updated inherited custody");
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("after snapshot");
    let mut after = native
        .stored_custody_policies_with_budget(
            &snapshot,
            child.event.event_id,
            &mut allowance(128 * 1024 * 1024),
        )
        .expect("current denied labels");
    assert!(after.iter().any(|policy| !policy.retrievable));
    assert_ne!(
        canonical_digest(&after).expect("changed domain"),
        frozen_domain
    );
    // The helper accepts a restriction set; digest ordering is not a method input.
    after.sort_by_key(|policy| policy.scopes.len());
    let forward = routing_scope_count(&after).expect("small label first");
    after.reverse();
    let reverse = routing_scope_count(&after).expect("large label first");
    assert_eq!((forward, reverse), (5, 5));
    let second = native
        .build_raw_bm25_documents(
            &snapshot,
            &original.event,
            receipt.workspace_commit,
            receipt.event_digest,
            &frozen_domain,
            reverse,
            &mut allowance(128 * 1024 * 1024),
        )
        .expect("historical source reconstruction after revocation");
    assert_eq!(
        first, second,
        "current permission and label ordering cannot retype the original's statistics"
    );
}
