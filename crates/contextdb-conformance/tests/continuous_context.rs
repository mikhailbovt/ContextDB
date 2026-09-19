//! Finite specification oracle from Continuous Context v3.
//!
//! These checks establish contract counterexamples. They do not execute native
//! durability, a concurrent lease owner, authentication or a model provider.

use std::collections::{BTreeMap, BTreeSet};

type Set = BTreeSet<&'static str>;
type Heads = BTreeMap<&'static str, Change>;

#[test]
fn shared_benchmark_history_keeps_query_time_inputs_separate_from_targets() {
    let history = contextdb_bench::continuous_history(256);
    let target = &history.evaluation[0];
    let query_events = history
        .events
        .iter()
        .filter(|event| event.scope == target.scope && event.known_at <= target.known_at)
        .collect::<Vec<_>>();
    assert_eq!(query_events.len(), 3);
    assert!(
        !query_events
            .iter()
            .any(|event| event.id == "atlas-correction")
    );
    assert!(
        query_events
            .iter()
            .any(|event| event.id == target.evidence_ids[0])
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Change {
    key: &'static str,
    sequence: u64,
    value: Option<&'static str>,
    effective_from: i64,
}

fn change(key: &'static str, sequence: u64, value: Option<&'static str>) -> Change {
    Change {
        key,
        sequence,
        value,
        effective_from: 0,
    }
}

fn replay(history: &[Change], known_at: u64, valid_at: i64) -> Heads {
    let mut ordered = history.to_vec();
    ordered.sort_by_key(|event| event.sequence);
    let mut heads = Heads::new();
    for event in ordered {
        if event.sequence <= known_at && event.effective_from <= valid_at {
            heads.insert(event.key, event);
        }
    }
    heads
}

fn overlay(
    base: &Heads,
    changes: &[Change],
    known_at: u64,
    valid_at: i64,
    allowed: &Set,
) -> BTreeMap<&'static str, &'static str> {
    let mut heads = base.clone();
    for event in changes {
        if event.sequence <= known_at
            && event.effective_from <= valid_at
            && heads
                .get(event.key)
                .is_none_or(|old| old.sequence < event.sequence)
        {
            heads.insert(event.key, *event);
        }
    }
    heads
        .into_iter()
        .filter_map(|(key, event)| {
            event
                .value
                .filter(|_| allowed.contains(key))
                .map(|value| (key, value))
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
struct Lease {
    epoch: u64,
    authorization: u64,
    valid_until: i64,
    hot: &'static str,
}

#[derive(Default)]
struct Authority {
    epoch: u64,
    authorization: u64,
}

impl Authority {
    fn admit(
        &self,
        epoch: u64,
        authorization: u64,
        valid_until: i64,
        now: i64,
        hot: &'static str,
    ) -> Result<Lease, &'static str> {
        if (epoch, authorization) != (self.epoch, self.authorization) {
            return Err("ConcurrentUpdateRetryable");
        }
        if now >= valid_until {
            return Err("LeaseExpired");
        }
        Ok(Lease {
            epoch,
            authorization,
            valid_until,
            hot,
        })
    }

    fn validate(&self, lease: Lease, now: i64, hot: &str) -> Result<(), &'static str> {
        if (lease.epoch, lease.authorization) != (self.epoch, self.authorization) {
            return Err("LeaseStale");
        }
        if now >= lease.valid_until {
            return Err("LeaseExpired");
        }
        if hot != lease.hot {
            return Err("LayoutChanged");
        }
        Ok(())
    }
}

fn closure(seeds: &Set, dependencies: &BTreeMap<&'static str, Set>) -> Result<Set, &'static str> {
    fn visit(
        id: &'static str,
        dependencies: &BTreeMap<&'static str, Set>,
        active: &mut Set,
        result: &mut Set,
    ) -> Result<(), &'static str> {
        let children = dependencies.get(id).ok_or("UnknownDependency")?;
        if active.contains(id) {
            return Err("DependencyCycle");
        }
        if result.contains(id) {
            return Ok(());
        }
        active.insert(id);
        for child in children {
            visit(child, dependencies, active, result)?;
        }
        active.remove(id);
        result.insert(id);
        Ok(())
    }
    let mut result = Set::new();
    for seed in seeds {
        visit(seed, dependencies, &mut Set::new(), &mut result)?;
    }
    Ok(result)
}

#[derive(Default)]
struct Capture {
    receipts: BTreeMap<(&'static str, &'static str), (Vec<u8>, u64)>,
}

impl Capture {
    fn append(
        &mut self,
        producer: &'static str,
        key: &'static str,
        bytes: &[u8],
    ) -> Result<u64, &'static str> {
        if let Some((previous, receipt)) = self.receipts.get(&(producer, key)) {
            return if previous == bytes {
                Ok(*receipt)
            } else {
                Err("IdempotencyConflict")
            };
        }
        let receipt = self.receipts.len() as u64 + 1;
        self.receipts
            .insert((producer, key), (bytes.to_vec(), receipt));
        Ok(receipt)
    }
}

#[test]
fn update_masks_old_current() {
    let base = replay(&[change("db", 1, Some("X"))], 1, 0);
    assert_eq!(
        overlay(
            &base,
            &[change("db", 2, Some("Y"))],
            2,
            0,
            &Set::from(["db"])
        ),
        BTreeMap::from([("db", "Y")])
    );
}

#[test]
fn tombstone_does_not_resurrect_old() {
    let base = replay(&[change("db", 1, Some("X"))], 1, 0);
    assert!(overlay(&base, &[change("db", 2, None)], 2, 0, &Set::from(["db"])).is_empty());
}

#[test]
fn overlay_matches_full_replay_in_12960_finite_cases() {
    let mut comparisons = 0;
    for pattern in 0_u64..6_u64.pow(4) {
        let history = (0..4)
            .map(|i| {
                let choice = (pattern / 6_u64.pow(i)) % 6;
                change(
                    if choice < 3 { "a" } else { "b" },
                    u64::from(i) + 1,
                    [None, Some("X"), Some("Y")][choice as usize % 3],
                )
            })
            .collect::<Vec<_>>();
        for cut in 0..=4 {
            let base = replay(&history[..cut], cut as u64, 0);
            for allowed in [Set::from(["a"]), Set::from(["a", "b"])] {
                let expected = replay(&history, 4, 0)
                    .into_iter()
                    .filter_map(|(key, event)| {
                        event
                            .value
                            .filter(|_| allowed.contains(key))
                            .map(|value| (key, value))
                    })
                    .collect::<BTreeMap<_, _>>();
                assert_eq!(overlay(&base, &history[cut..], 4, 0, &allowed), expected);
                comparisons += 1;
            }
        }
    }
    assert_eq!(comparisons, 12_960);
}

#[test]
fn future_effective_value_needs_clock_check() {
    let history = [
        change("mode", 1, Some("old")),
        Change {
            effective_from: 10,
            ..change("mode", 2, Some("new"))
        },
    ];
    assert_eq!(replay(&history, 2, 9)["mode"].value, Some("old"));
    assert_eq!(replay(&history, 2, 10)["mode"].value, Some("new"));
    let authority = Authority::default();
    let lease = authority.admit(0, 0, 10, 9, "H").expect("admitted");
    assert_eq!(authority.validate(lease, 10, "H"), Err("LeaseExpired"));
}

#[test]
fn historical_knowledge_uses_current_permission() {
    let base = replay(&[change("secret", 1, Some("private"))], 1, 0);
    assert!(overlay(&base, &[], 1, 0, &Set::new()).is_empty());
}

#[test]
fn lost_notification_cannot_admit_stale_compilation() {
    let mut authority = Authority::default();
    let read = authority.epoch;
    authority.epoch += 1;
    assert_eq!(
        authority
            .admit(read, 0, 100, 0, "H")
            .expect_err("write preceded registration"),
        "ConcurrentUpdateRetryable"
    );
}

#[test]
fn single_write_all_lease_interleavings() {
    for slot in 0..4 {
        let mut operations = vec!["read", "register", "validate"];
        operations.insert(slot, "write");
        let mut authority = Authority::default();
        let mut read = 0;
        let mut lease = None;
        let mut rejected = false;
        for operation in operations {
            match operation {
                "write" => authority.epoch += 1,
                "read" => read = authority.epoch,
                "register" => match authority.admit(read, 0, 100, 0, "H") {
                    Ok(value) => lease = Some(value),
                    Err(_) => rejected = true,
                },
                _ => {
                    if let Some(value) = lease {
                        rejected |= authority.validate(value, 0, "H").is_err();
                    }
                }
            }
        }
        // A write after validation exposes the separate external-dispatch gap.
        assert_eq!(rejected, slot == 1 || slot == 2);
    }
}

#[test]
fn revocation_invalidates_lease() {
    let mut authority = Authority::default();
    let lease = authority.admit(0, 0, 100, 0, "H").expect("lease");
    authority.authorization += 1;
    assert_eq!(authority.validate(lease, 0, "H"), Err("LeaseStale"));
}

#[test]
fn hot_change_invalidates_lease() {
    let authority = Authority::default();
    let lease = authority.admit(0, 0, 100, 0, "before").expect("lease");
    assert_eq!(authority.validate(lease, 0, "after"), Err("LayoutChanged"));
}

#[test]
fn post_eviction_routing_preserves_required_source() {
    let required = Set::from(["fact"]);
    let old_hot = required.clone();
    let future_hot = Set::new();
    let wrong = required.difference(&old_hot).copied().collect::<Set>();
    assert!(!required.is_subset(&wrong.union(&future_hot).copied().collect()));
    let selected = required.difference(&future_hot).copied().collect::<Set>();
    assert!(required.is_subset(&selected));
}

#[test]
fn all_64_small_hot_visibility_sets() {
    let sets = (0..8)
        .map(|mask| {
            ["a", "b", "c"]
                .into_iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, id)| id)
                .collect::<Set>()
        })
        .collect::<Vec<_>>();
    for required in &sets {
        for hot in &sets {
            let selected = required.difference(hot).copied().collect::<Set>();
            assert!(required.is_subset(&selected.union(hot).copied().collect()));
            assert!(selected.is_disjoint(hot));
        }
    }
}

#[test]
fn stop_keeps_mandatory_evidence_closure() {
    let dependencies = BTreeMap::from([
        ("decision", Set::from(["proof"])),
        ("proof", Set::new()),
        ("optional", Set::new()),
    ]);
    assert_eq!(
        closure(&Set::from(["decision"]), &dependencies),
        Ok(Set::from(["decision", "proof"]))
    );
    assert_eq!(closure(&Set::new(), &dependencies), Ok(Set::new()));
}

#[test]
fn dependency_cycle_is_not_infinite_loop() {
    let dependencies = BTreeMap::from([("a", Set::from(["b"])), ("b", Set::from(["a"]))]);
    assert_eq!(
        closure(&Set::from(["a"]), &dependencies),
        Err("DependencyCycle")
    );
}

#[test]
fn unknown_dependency_is_rejected() {
    assert_eq!(
        closure(
            &Set::from(["a"]),
            &BTreeMap::from([("a", Set::from(["missing"]))])
        ),
        Err("UnknownDependency")
    );
}

#[test]
fn shared_support_is_charged_once() {
    let selected = closure(
        &Set::from(["a", "b"]),
        &BTreeMap::from([
            ("a", Set::from(["proof"])),
            ("b", Set::from(["proof"])),
            ("proof", Set::new()),
        ]),
    )
    .expect("closure");
    let costs = BTreeMap::from([("a", 3), ("b", 4), ("proof", 8)]);
    assert_eq!(selected.iter().map(|id| costs[id]).sum::<u32>(), 15);
    assert_eq!(
        selected
            .difference(&Set::from(["proof"]))
            .map(|id| costs[id])
            .sum::<u32>(),
        7
    );
}

#[test]
fn hot_secret_is_not_hidden_by_clean_pack() {
    let zones = [Set::from(["public"]), Set::from(["secret"])];
    let allowed = Set::from(["public"]);
    assert!(zones[0].is_subset(&allowed));
    assert!(!zones.iter().all(|zone| zone.is_subset(&allowed)));
}

#[test]
fn repeated_exposure_is_not_independent_corroboration() {
    let occurrences = (0..100).map(|i| (i, "original-1")).collect::<Vec<_>>();
    assert_eq!(occurrences.len(), 100);
    assert_eq!(
        occurrences
            .iter()
            .map(|(_, root)| root)
            .collect::<BTreeSet<_>>()
            .len(),
        1
    );
}

#[test]
fn order_is_part_of_input_manifest() {
    let first = serde_json::to_vec(&["a", "b"]).expect("manifest");
    let second = serde_json::to_vec(&["b", "a"]).expect("manifest");
    assert_ne!(blake3::hash(&first), blake3::hash(&second));
}

#[test]
fn commit_response_loss_retries_same_receipt() {
    let mut store = Capture::default();
    let lost = store.append("p", "key", b"original").expect("committed");
    assert_eq!(store.append("p", "key", b"original"), Ok(lost));
    assert_eq!(store.receipts.len(), 1);
}

#[test]
fn same_text_different_occurrence_is_retained() {
    let mut store = Capture::default();
    assert_ne!(
        store.append("p", "one", b"same"),
        store.append("p", "two", b"same")
    );
}

#[test]
fn same_identity_different_bytes_conflicts() {
    let mut store = Capture::default();
    store.append("p", "one", b"first").expect("committed");
    assert_eq!(
        store.append("p", "one", b"other"),
        Err("IdempotencyConflict")
    );
}

#[test]
fn topk_cannot_certify_full_enumeration() {
    let all = Set::from(["1", "2", "3", "4", "5"]);
    let page = Set::from(["1", "2", "3"]);
    let count = |returned: &Set, complete: bool| {
        if complete && returned == &all {
            Ok(returned.len())
        } else {
            Err("EnumerationIncomplete")
        }
    };
    assert!(count(&page, false).is_err());
    assert!(count(&page, true).is_err());
    assert_eq!(count(&all, true), Ok(5));
}

#[test]
fn temporal_read_does_not_include_future_commit() {
    let history = [change("a", 1, Some("past")), change("a", 3, Some("future"))];
    assert_eq!(replay(&history, 2, 0)["a"].value, Some("past"));
}
