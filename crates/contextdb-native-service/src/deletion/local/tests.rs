use super::*;
use crate::capture::tests::request;
use crate::retention::keys::witness::tests::{budget, fixture};
use contextdb_service::CapturePort;

#[test]
fn local_removal_inventory_checks_current_authority_budget_and_native_frontier() {
    let f = fixture();
    let context = &f.input.context;
    let before = f.native.engine.head_sequence().expect("head");
    let mut denied = context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        f.native
            .read_original_removal_local_inventory(&denied, &f.removal, &mut budget())
            .expect_err("Admin before inventory")
            .code,
        ErrorCode::Unauthorized
    );
    let mut scope = context.clone();
    scope.request.workspace_id = "different-workspace".into();
    assert!(
        f.native
            .read_original_removal_local_inventory(&scope, &f.removal, &mut budget())
            .is_err()
    );
    let mut wrong = f.removal.clone();
    wrong.digest = "ab".repeat(32);
    assert!(
        f.native
            .read_original_removal_local_inventory(context, &wrong, &mut budget())
            .is_err()
    );
    let mut empty = QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert_eq!(
        f.native
            .read_original_removal_local_inventory(context, &f.removal, &mut empty)
            .expect_err("bounded")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(
        f.native.engine.head_sequence().expect("no mutation"),
        before
    );
    for physical_only in [false, true] {
        let native = f.native.clone();
        BEFORE_CURRENT_CHECK.with(|hook| {
            hook.replace(Some(Box::new(move || {
                if physical_only {
                    native
                        .engine
                        .begin_write()
                        .expect("tx")
                        .commit(Durability::Sync)
                        .expect("physical frontier");
                } else {
                    native
                        .append_event(request(3, "unrelated concurrent capture"))
                        .expect("capture");
                }
            })));
        });
        assert_eq!(
            f.native
                .read_original_removal_local_inventory(context, &f.removal, &mut budget())
                .expect_err("inventory retries on native publication")
                .code,
            ErrorCode::IndexTooStale
        );
    }
    let valid = f
        .native
        .read_original_removal_local_inventory(context, &f.removal, &mut budget())
        .expect("current report");
    assert_eq!(valid.sources.len(), 1);
    assert!(valid.absent_sources.is_empty());
}
