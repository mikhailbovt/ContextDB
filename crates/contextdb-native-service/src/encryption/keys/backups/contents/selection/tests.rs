use super::super::tests::{archive, legacy_registry, populated};
use super::*;
use crate::raw_index::copies::tests::budget;

#[test]
fn archive_selection_preserves_unknown_coverage_and_fences_membership_only_growth() {
    let f = populated();
    let old = archive(&f);
    let original_empty = f
        .keys
        .backup_contents(&f.empty.digest, &mut budget())
        .expect("initial control rows")
        .expect("original membership");
    legacy_registry(&f.keys, true);
    let selected = BTreeMap::new();
    let unknown = f
        .keys
        .selected_backup_keys(&selected, &mut budget())
        .expect("legacy catalog");
    assert_eq!(unknown.archives.len(), 2);
    assert!(
        unknown
            .archives
            .iter()
            .all(|archive| archive.contents.is_none() && archive.copies.is_empty())
    );
    f.native
        .retain_backup_contents(&f.first.context, &old, &mut budget())
        .expect("verified backfill");
    assert_eq!(
        f.keys
            .require_backup_frontier(&unknown.frontier, &mut budget())
            .expect_err("backfill alone invalidates archive coverage")
            .code,
        ErrorCode::IndexTooStale
    );
    let known = f
        .keys
        .selected_backup_keys(&selected, &mut budget())
        .expect("backfilled catalog");
    assert_eq!(
        unknown.frontier.issued_sequence,
        known.frontier.issued_sequence
    );
    assert_eq!(unknown.frontier.issued_digest, known.frontier.issued_digest);
    assert_ne!(unknown.frontier.contents, known.frontier.contents);
    assert!(
        known.archives[0].contents.is_none(),
        "older empty archive is still unverified"
    );
    assert!(
        known.archives[1]
            .contents
            .as_ref()
            .expect("full membership")
            .pages
            > 1
    );
    assert!(
        known.archives[1].copies.is_empty(),
        "empty selection, verified archive"
    );
    f.native
        .retain_backup_contents(&f.first.context, &f.empty, &mut budget())
        .expect("empty backfill");
    let complete = f
        .keys
        .selected_backup_keys(&selected, &mut budget())
        .expect("all verified");
    assert!(
        complete
            .archives
            .iter()
            .all(|archive| archive.contents.is_some())
    );
    assert_eq!(
        complete.archives[0]
            .contents
            .as_ref()
            .expect("empty receipt")
            .rows,
        original_empty.rows
    );
    assert!(
        original_empty.rows > 0,
        "an unused native store still has control rows"
    );
    let mut exhausted =
        QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert_eq!(
        f.keys
            .selected_backup_keys(&selected, &mut exhausted)
            .expect_err("bounded work")
            .code,
        ErrorCode::BudgetExhausted
    );
}

#[test]
fn archive_selection_validates_unselected_pages_and_complete_reverse_closure() {
    let f = populated();
    let old = archive(&f);
    let accepted = f
        .keys
        .backup_contents(&old.digest, &mut budget())
        .expect("contents")
        .expect("accepted");
    let selected = BTreeMap::new();
    let baseline = f
        .keys
        .selected_backup_keys(&selected, &mut budget())
        .expect("baseline");
    for key in [
        page_key(accepted.receipt.sequence, 1),
        event_key(accepted.receipt.sequence),
        index_key(&old.digest),
        super::super::super::index_key(&f.empty.digest),
        issued_key(accepted.registration.sequence),
    ] {
        let mut tx = f.keys.engine.begin_write().expect("tx");
        let bytes = tx.get(&f.keys.rows, &key).expect("row").expect("present");
        tx.delete(&f.keys.rows, key.clone()).expect("loss");
        tx.commit(Durability::Sync).expect("commit fault");
        assert!(
            f.keys
                .selected_backup_keys(&selected, &mut budget())
                .is_err(),
            "even an empty selection requires all accepted archive rows"
        );
        let mut tx = f.keys.engine.begin_write().expect("repair tx");
        tx.put(&f.keys.rows, key, bytes)
            .expect("restore exact bytes");
        tx.commit(Durability::Sync).expect("repair fixture");
    }
    assert_eq!(
        f.keys
            .selected_backup_keys(&selected, &mut budget())
            .expect("repaired"),
        baseline
    );
    let key = b"backup/contents/page/undeclared".to_vec();
    let mut tx = f.keys.engine.begin_write().expect("tx");
    tx.put(&f.keys.rows, key, b"orphan".to_vec())
        .expect("orphan");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        f.keys
            .selected_backup_keys(&selected, &mut budget())
            .expect_err("reverse closure")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn archive_selection_matches_key_and_address_without_inferring_native_use() {
    let f = populated();
    let old = archive(&f);
    let accepted = f
        .keys
        .backup_contents(&old.digest, &mut budget())
        .expect("contents")
        .expect("accepted");
    let all = f
        .keys
        .backup_contents_page(&accepted.receipt, 0, &mut budget())
        .expect("page");
    let copy = all
        .copies
        .first()
        .expect("actual archived ciphertext")
        .clone();
    let selected = BTreeMap::from([(copy.version.key_id, copy.address_digest.clone())]);
    let report = f
        .keys
        .selected_backup_keys(&selected, &mut budget())
        .expect("exact key");
    assert_eq!(report.archives[1].copies, vec![copy.clone()]);
    assert!(report.archives[0].copies.is_empty());
    let wrong = BTreeMap::from([(copy.version.key_id, "ff".repeat(32))]);
    assert_eq!(
        f.keys
            .selected_backup_keys(&wrong, &mut budget())
            .expect_err("address substitution")
            .code,
        ErrorCode::IntegrityFailure
    );
}
