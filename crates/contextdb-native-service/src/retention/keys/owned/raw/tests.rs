use super::*;
use crate::raw_index::copies::tests::{budget, fixture, reclaim};
use crate::raw_index::inventory::tests::{gather, request};

#[test]
fn raw_decisions_freeze_coverage_retry_and_reopen_both_authorities() {
    let f = fixture();
    while !reclaim(&f, 64).finished {}
    let context = &f.first.context;
    let removal = request(&f);
    let report = f
        .native
        .read_reclaimed_raw_key_inventory(context, &removal, &mut budget())
        .expect("GC coverage");
    let frontier = report.observation_frontier();
    let reclaimed = f
        .native
        .retain_reclaimed_raw_key_removal(context, &removal, &frontier, &mut budget())
        .expect("GC decisions");
    let pages = gather(&f.native, context, &removal);
    let terminal = &pages.last().expect("terminal").receipt;
    let inspected = f
        .native
        .retain_raw_index_key_removal(context, &removal, terminal, &mut budget())
        .expect("inspection decisions");
    let before = f.native.verify_native(true).expect("native state");
    for decision in [&reclaimed, &inspected] {
        assert!(!decision.dispositions.is_empty());
        assert!(
            decision
                .dispositions
                .values()
                .flatten()
                .all(|key| !key.versions.is_empty())
        );
        let serialized = String::from_utf8(encode(decision).expect("JSON")).expect("UTF8");
        assert!(!serialized.contains("rawcopysentinelprivate"));
        assert!(!serialized.contains("rawcopysentinelindependent"));
    }
    // A second observation is possible after a lost GC acknowledgement. It grows
    // coverage without changing native data or either custody frontier.
    let page = f
        .native
        .read_raw_copy_witness(context, &report.witnesses[0], &mut budget())
        .expect("retained observation");
    let duplicate = f
        .ledger
        .retain_raw_copy_witness(&page, &mut budget())
        .expect("later observation");
    assert_eq!(
        f.native
            .retain_reclaimed_raw_key_removal(context, &removal, &frontier, &mut budget())
            .expect("same prefix, even after own acceptance and later observations"),
        reclaimed
    );
    assert_eq!(
        f.native
            .retain_raw_index_key_removal(context, &removal, terminal, &mut budget())
            .expect("same inspection"),
        inspected
    );
    let later = f
        .native
        .read_reclaimed_raw_key_inventory(context, &removal, &mut budget())
        .expect("expanded observation coverage");
    assert!(later.witnesses.contains(&duplicate));
    let later_decisions = f
        .native
        .retain_reclaimed_raw_key_removal(
            context,
            &removal,
            &later.observation_frontier(),
            &mut budget(),
        )
        .expect("explicit newer prefix");
    assert_ne!(later_decisions.receipt, reclaimed.receipt);
    assert_eq!(later_decisions.dispositions, reclaimed.dispositions);
    assert_eq!(
        f.native.verify_native(true).expect("after").archive_digest,
        before.archive_digest
    );
    let key_id = f.keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.keys_directory.path().join("keys"),
        "raw-copies",
        key_id,
        CustodyMasterKey::from_zeroizing(Zeroizing::new([79; 32])).expect("master"),
    )
    .expect("custody reopened");
    let ledger = NativeSuppressionLedger::open(
        f.ledger_directory.path().join("ledger"),
        "raw-copies",
        ledger_id,
    )
    .expect("removal authority reopened");
    let native = NativeService::open_encrypted(
        f.root.path().join("native"),
        "raw-copies",
        [8; 32],
        ledger,
        keys,
    )
    .expect("native reopened with new token key");
    assert_eq!(
        native
            .read_reclaimed_raw_key_removal(
                context,
                &removal,
                &frontier,
                &reclaimed.receipt,
                &mut budget()
            )
            .expect("historical GC decisions"),
        reclaimed
    );
    assert_eq!(
        native
            .read_raw_index_key_removal(
                context,
                &removal,
                terminal,
                &inspected.receipt,
                &mut budget()
            )
            .expect("historical inspection decisions"),
        inspected
    );
}

#[test]
fn raw_decisions_require_complete_authorized_coverage() {
    let f = fixture();
    while !reclaim(&f, 64).finished {}
    let context = &f.first.context;
    let removal = request(&f);
    let frontier = f
        .native
        .read_reclaimed_raw_key_inventory(context, &removal, &mut budget())
        .expect("GC coverage")
        .observation_frontier();
    let pages = gather(&f.native, context, &removal);
    let terminal = &pages.last().expect("terminal").receipt;
    let reclaimed = f
        .native
        .retain_reclaimed_raw_key_removal(context, &removal, &frontier, &mut budget())
        .expect("GC decisions");
    let inspected = f
        .native
        .retain_raw_index_key_removal(context, &removal, terminal, &mut budget())
        .expect("inspection decisions");
    assert!(
        f.native
            .retain_raw_index_key_removal(context, &removal, &pages[0].receipt, &mut budget())
            .is_err(),
        "a partial inspection is not complete coverage"
    );
    for fault in ["authority", "sequence", "digest"] {
        let mut wrong = frontier.clone();
        match fault {
            "authority" => wrong.authority_id = uuid::Uuid::max(),
            "sequence" => wrong.sequence = u64::MAX,
            "digest" => wrong.digest = "ab".repeat(32),
            _ => unreachable!(),
        }
        assert!(
            f.native
                .retain_reclaimed_raw_key_removal(context, &removal, &wrong, &mut budget())
                .is_err(),
            "{fault}"
        );
    }
    for fault in ["admin", "workspace"] {
        let mut denied = context.clone();
        if fault == "admin" {
            denied.capability_grants.remove(&Capability::Admin);
        } else {
            denied.request.workspace_id = "other-workspace".into();
        }
        assert!(
            f.native
                .retain_reclaimed_raw_key_removal(&denied, &removal, &frontier, &mut budget())
                .is_err(),
            "{fault}"
        );
        assert!(
            f.native
                .read_reclaimed_raw_key_removal(
                    &denied,
                    &removal,
                    &frontier,
                    &reclaimed.receipt,
                    &mut budget()
                )
                .is_err(),
            "{fault}"
        );
        assert!(
            f.native
                .retain_raw_index_key_removal(&denied, &removal, terminal, &mut budget())
                .is_err(),
            "{fault}"
        );
        assert!(
            f.native
                .read_raw_index_key_removal(
                    &denied,
                    &removal,
                    terminal,
                    &inspected.receipt,
                    &mut budget()
                )
                .is_err(),
            "{fault}"
        );
    }
    assert!(
        f.native
            .read_reclaimed_raw_key_removal(
                context,
                &removal,
                &frontier,
                &inspected.receipt,
                &mut budget()
            )
            .is_err(),
        "receipt cannot substitute another kind of coverage"
    );
    let other = f
        .native
        .request_original_removal(
            context,
            &BTreeSet::from([f.independent.event.event_id]),
            "other-request",
            &mut budget(),
        )
        .expect("other removal");
    assert!(
        f.native
            .read_reclaimed_raw_key_removal(
                context,
                &other,
                &frontier,
                &reclaimed.receipt,
                &mut budget()
            )
            .is_err()
    );
    assert!(
        f.native
            .retain_raw_index_key_removal(context, &other, terminal, &mut budget())
            .is_err()
    );
    let mut tiny = QueryBudget::new(0, 0, std::time::Duration::from_secs(5), Default::default());
    assert_eq!(
        f.native
            .retain_reclaimed_raw_key_removal(context, &removal, &frontier, &mut tiny)
            .expect_err("budget")
            .code,
        ErrorCode::BudgetExhausted
    );
}
