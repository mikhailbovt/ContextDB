use super::*;
use crate::raw_index::copies::tests::{budget, fixture, reclaim};
use crate::raw_index::inventory::tests::{gather, request};

#[test]
fn raw_decisions_reject_rehashed_source_version_and_coverage_claims() {
    for inspection in [false, true] {
        for fault in ["source", "version", "address", "coverage"] {
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
            let decision = if inspection {
                f.native
                    .retain_raw_index_key_removal(context, &removal, terminal, &mut budget())
            } else {
                f.native.retain_reclaimed_raw_key_removal(
                    context,
                    &removal,
                    &frontier,
                    &mut budget(),
                )
            }
            .expect("retain");
            let mut inventory = decision.inventory.clone();
            if fault == "coverage" {
                match &mut inventory.owner {
                    NativeOwnedKeyOwner::ReclaimedRaw { witnesses, .. } => {
                        witnesses.pop().expect("observation");
                    }
                    NativeOwnedKeyOwner::InspectedRaw {
                        inspected_pages, ..
                    } => {
                        *inspected_pages -= 1;
                    }
                    _ => unreachable!(),
                }
            } else {
                let sources = match &mut inventory.owner {
                    NativeOwnedKeyOwner::ReclaimedRaw { sources, .. }
                    | NativeOwnedKeyOwner::InspectedRaw { sources, .. } => sources,
                    _ => unreachable!(),
                };
                if fault == "source" {
                    let rows = sources.remove(&f.first.event.event_id).expect("source");
                    sources.insert(f.independent.event.event_id, rows);
                } else {
                    let rows = sources.values_mut().next().expect("source");
                    if fault == "address" {
                        // Omit allocations and use together so only the independently
                        // reconstructed raw coverage exposes the missing family.
                        let (address, _) = rows.pop_first().expect("address");
                        inventory
                            .native_use
                            .addresses
                            .remove(&address)
                            .expect("use");
                    } else {
                        rows.values_mut()
                            .next()
                            .expect("family")
                            .observed_versions
                            .clear();
                    }
                }
            }
            let receipt = tests::replace_inventory(&f.ledger, &decision.receipt, &inventory);
            assert!(f.ledger.verify().is_err(), "{inspection}/{fault}");
            let result = if inspection {
                f.native.read_raw_index_key_removal(
                    context,
                    &removal,
                    terminal,
                    &receipt,
                    &mut budget(),
                )
            } else {
                f.native.read_reclaimed_raw_key_removal(
                    context,
                    &removal,
                    &frontier,
                    &receipt,
                    &mut budget(),
                )
            };
            assert_eq!(
                result.expect_err(fault).code,
                ErrorCode::IntegrityFailure,
                "{inspection}/{fault}"
            );
        }
    }
}
