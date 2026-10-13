use super::*;
use contextdb_context::router::RouterDecision;
use contextdb_recall::QueryCancellation;
use std::time::Duration;

fn allowance() -> QueryBudget {
    QueryBudget::new(
        20_000_000,
        2 * 1024 * 1024 * 1024,
        Duration::from_secs(40),
        Default::default(),
    )
}

fn replace_artifact(root: &Path, name: &str, bytes: &[u8]) {
    let mut manifest: Manifest = decode(
        &fs::read(root.join(MANIFEST)).expect("manifest"),
        MAX_ROUTER_TARGET_BYTES,
        &mut allowance(),
    )
    .expect("canonical manifest");
    manifest.artifacts.insert(
        name.into(),
        Artifact {
            bytes: bytes.len() as u64,
            digest: ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes()),
        },
    );
    fs::write(root.join(name), bytes).expect("rehash supplied artifact");
    fs::write(
        root.join(MANIFEST),
        router_corpus_bytes(&manifest, MAX_ROUTER_TARGET_BYTES, &mut allowance())
            .expect("rehash supplied metadata"),
    )
    .expect("untrusted hash is not authority");
}

#[test]
fn builtin_cold_roundtrip_reuses_completed_job_and_preserves_separated_unknown_labels() {
    let temp = tempfile::tempdir().expect("owned fixture root");
    let parent = fs::canonicalize(temp.path()).expect("canonical owned fixture parent");
    validate_root(&parent, true).expect("fixture parent passes strict path admission");
    let root = parent.join("corpus");
    let built =
        write_builtin_router_corpus(&root, &mut allowance()).expect("actual compiler corpus");
    assert_eq!(built.examples, 32);
    assert_eq!(
        (built.train, built.validation, built.test, built.quarantined),
        (8, 8, 8, 8)
    );
    assert!(!built.trained_router);
    let manifest = fs::read(root.join(MANIFEST)).expect("final completion manifest");
    assert_eq!(
        built,
        verify_builtin_router_corpus(&root, &mut allowance()).expect("cold validation")
    );
    assert_eq!(
        built,
        write_builtin_router_corpus(&root, &mut allowance()).expect("lost acknowledgement retry")
    );
    assert_eq!(
        manifest,
        fs::read(root.join(MANIFEST)).expect("unchanged manifest")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let alias = parent.join("owned-parent-alias");
        symlink(&parent, &alias).expect("controlled owned parent alias");
        assert!(write_builtin_router_corpus(&alias.join("corpus"), &mut allowance()).is_err());
        let canonical = fs::canonicalize(&alias).expect("resolve owned fixture alias");
        assert_eq!(
            built,
            verify_builtin_router_corpus(&canonical.join("corpus"), &mut allowance())
                .expect("canonical alias resolves the same completed job")
        );
    }
    let observed: Vec<RouterBehaviorRecord> = decode(
        &fs::read(root.join("behavior.json")).expect("behavior"),
        MAX_ROUTER_EXAMPLE_BYTES,
        &mut allowance(),
    )
    .expect("behavior transport");
    let resident = observed
        .iter()
        .find(|item| item.example_id == "group-0-ResidentCode")
        .expect("resident occurrence");
    assert_eq!(resident.plan.decision, RouterDecision::Stop);
    assert!(resident.plan.behavior_propensity.is_none());
    let labels: Vec<RouterUtilityTargets> = decode(
        &fs::read(root.join("targets.json")).expect("labels"),
        MAX_ROUTER_EXAMPLE_BYTES,
        &mut allowance(),
    )
    .expect("independent labels");
    let complement = labels
        .iter()
        .find(|item| item.example_id == "group-0-Complement")
        .expect("complement");
    assert!(
        complement
            .bundles
            .iter()
            .any(|item| item.useful == Some(true))
    );
    for member in &complement.bundles[0].members {
        assert!(
            complement
                .candidates
                .iter()
                .any(|item| &item.candidate_id == member && item.useful.is_none())
        );
    }
    let multiple = labels
        .iter()
        .find(|item| item.example_id == "group-0-MultiMemory")
        .expect("independent multi-positive labels");
    assert_eq!(
        multiple
            .candidates
            .iter()
            .filter(|item| item.useful == Some(true))
            .count(),
        2
    );
    let zero = labels
        .iter()
        .find(|item| item.example_id == "group-0-NoMemory")
        .expect("all-zero optional case");
    assert!(zero.candidates.iter().all(|item| item.useful != Some(true)));
    let original_labels = fs::read(root.join("targets.json")).expect("original target artifact");
    let mut forged = labels;
    let provenance = forged
        .iter_mut()
        .flat_map(|item| &mut item.candidates)
        .find_map(|item| item.provenance.as_mut())
        .expect("known provenance");
    provenance.source_nodes[0].id = "nonexistent-source-root".into();
    provenance.source_nodes.sort();
    replace_artifact(
        &root,
        "targets.json",
        &router_corpus_bytes(&forged, MAX_ROUTER_EXAMPLE_BYTES, &mut allowance())
            .expect("structurally valid forged target"),
    );
    assert!(verify_builtin_router_corpus(&root, &mut allowance()).is_err());
    replace_artifact(&root, "targets.json", &original_labels);
    let original_lineage = fs::read(root.join("lineage.json")).expect("original lineage artifact");
    let mut broken: Lineage = decode(
        &original_lineage,
        MAX_ROUTER_EXAMPLE_BYTES,
        &mut allowance(),
    )
    .expect("lineage graph");
    broken
        .nodes
        .iter_mut()
        .find(|node| node.reference.kind == RouterLineageKind::Evaluation)
        .expect("evaluation derivation")
        .parents
        .pop();
    replace_artifact(
        &root,
        "lineage.json",
        &router_corpus_bytes(&broken, MAX_ROUTER_EXAMPLE_BYTES, &mut allowance())
            .expect("forged evaluation parents"),
    );
    assert!(verify_builtin_router_corpus(&root, &mut allowance()).is_err());
    replace_artifact(&root, "lineage.json", &original_lineage);
    assert_eq!(
        built,
        verify_builtin_router_corpus(&root, &mut allowance()).expect("restored exact artifacts")
    );
    fs::write(root.join("features.json"), b"[]").expect("corrupt retained artifact");
    assert!(verify_builtin_router_corpus(&root, &mut allowance()).is_err());
    assert!(write_builtin_router_corpus(&root, &mut allowance()).is_err());
}

#[test]
fn incomplete_roots_bounds_and_cancellation_are_closed_without_overwrite() {
    let temp = tempfile::tempdir().expect("owned fixture root");
    let parent = fs::canonicalize(temp.path()).expect("canonical owned fixture parent");
    validate_root(&parent, true).expect("fixture parent passes strict path admission");
    let incomplete = parent.join("incomplete");
    fs::create_dir(&incomplete).expect("incomplete directory");
    fs::write(
        incomplete.join("query-time.json.part"),
        b"SYNTHETIC_PENDING",
    )
    .expect("partial owned artifact");
    assert!(write_builtin_router_corpus(&incomplete, &mut allowance()).is_err());
    assert_eq!(
        fs::read(incomplete.join("query-time.json.part")).expect("preserved incomplete"),
        b"SYNTHETIC_PENDING"
    );
    let fresh = parent.join("cancelled");
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(
        1_000_000,
        256 * 1024 * 1024,
        Duration::from_secs(10),
        cancellation,
    );
    assert!(matches!(
        write_builtin_router_corpus(&fresh, &mut cancelled),
        Err(BenchError::TelemetryBudget(_))
    ));
    assert!(!fresh.exists());
    let mut exhausted = QueryBudget::new(1_000_000, 1, Duration::from_secs(10), Default::default());
    assert!(matches!(
        write_builtin_router_corpus(&fresh, &mut exhausted),
        Err(BenchError::TelemetryBudget(_))
    ));
    assert!(!fresh.exists());
    assert!(write_builtin_router_corpus(Path::new("relative-output"), &mut allowance()).is_err());
    let nonfile = incomplete.join(MANIFEST);
    fs::create_dir(nonfile).expect("invalid manifest type");
    assert!(verify_builtin_router_corpus(&incomplete, &mut allowance()).is_err());
}
