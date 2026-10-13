use super::*;
use crate::{NativeArchiveMaintenanceAuthority, NativeArchiveScopeResolver};

#[derive(Debug)]
struct Authority(AuthenticatedRequestContext);

impl NativeArchiveMaintenanceAuthority for Authority {
    fn context(
        &self,
        workspace: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AuthenticatedRequestContext> {
        budget.check().map_err(raw_index::budget_error)?;
        if self.0.request.workspace_id != workspace {
            return Err(permission_denied());
        }
        Ok(self.0.clone())
    }
}

fn held_ledger(
    ledger: std::sync::Arc<NativeSuppressionLedger>,
    frontier: RemovalCheckpoint,
) -> Box<dyn FnOnce() -> ServiceResult<()>> {
    Box::new(move || {
        let mut bounded = QueryBudget::new(
            1000,
            1024 * 1024,
            std::time::Duration::from_millis(30),
            Default::default(),
        );
        let Err(error) = ledger.lock_removal_frontier(&frontier, &mut bounded) else {
            panic!("actual ledger admission escaped its custody Sync fence")
        };
        assert_eq!(error.code, ErrorCode::BudgetExhausted);
        assert!(error.message.contains("deadline"));
        Ok(())
    })
}

#[test]
fn scoped_retirement_requires_current_removal_frontier_at_custody_acceptance() {
    let f = fixture();
    let view = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("old actual view");
    let space = f.native.keyspaces.observations_content.clone();
    let selected = ids(&f);
    prune(&f, &f.removal);
    let authority = Authority(f.input.context.clone());
    let workspace = f.input.context.request.workspace_id.clone();
    let resolver = NativeArchiveScopeResolver::new(std::slice::from_ref(&workspace), &authority)
        .expect("host resolver");
    let native = f.native.clone();
    let context = f.input.context.clone();
    BEFORE_RETIREMENT_FENCE.with(|hook| {
        hook.replace(Some(Box::new(move || {
            native
                .request_original_removal(
                    &context,
                    &BTreeSet::from([request(2, "").event.event_id]),
                    "changed removal authority after scoped report",
                    &mut budget(),
                )
                .expect("actual concurrent accepted request");
        })))
    });
    let retire = || {
        f.native.retire_removal_keys_with_scope_authority(
            &workspace,
            &f.removal,
            &NativeRemovalKeySelection::Originals,
            &selected,
            &resolver,
            &mut budget(),
        )
    };
    assert_eq!(
        retire()
            .expect_err("scope frame became stale before custody Sync")
            .code,
        ErrorCode::IndexTooStale
    );
    assert!(
        view.get(&space, &source_key(1))
            .expect("stale admission did not retire a key")
            .is_some()
    );
    let current = f
        .native
        .read_original_removal_requests(&f.input.context, &mut budget())
        .expect("exact current removal frontier");
    let frontier = RemovalCheckpoint {
        sequence: current.sequence,
        digest: current.digest,
    };
    encryption::BEFORE_RETIREMENT_SYNC
        .with(|hook| hook.replace(Some(held_ledger(f.ledger.clone(), frontier.clone()))));
    encryption::AFTER_RETIREMENT_DURABLE
        .with(|hook| hook.replace(Some(held_ledger(f.ledger.clone(), frontier))));
    let accepted = retire().expect("fresh host operation frame stays fenced through real Sync");
    assert!(
        accepted.evidence.classification.is_none(),
        "ordinary scoped refusal does not fabricate classification evidence"
    );
    assert!(
        view.get(&space, &source_key(1))
            .expect_err("actual refusal covers old views")
            .to_string()
            .contains("retired")
    );
    assert_eq!(retire().expect("exact retained retry"), accepted);
    f.native
        .verify_native(true)
        .expect("native history after frontier race");
}
