#![allow(
    clippy::expect_used,
    clippy::too_many_arguments,
    clippy::unwrap_used,
    reason = "test fixtures use immediate failure semantics"
)]

use std::collections::BTreeSet;

use contextdb_core::{ContentDigest, EvidenceId, TimestampMicros};

use crate::{
    CiRun, CiRunId, CodeDomainProjection, CodeMemory, CodeQuery, CodeRelation, CodeRelationKind,
    DecisionId, DecisionRecord, FileIdentity, FileRevision, GitChangeKind, GitCommitDescriptor,
    GoCompilerIndex, GoIndexSymbol, GoSnapshotAdapter, GoSourceFile, Language, PortableCodeMemory,
    RationaleResult, RepoPath, RepositoryDescriptor, RepositoryId, RepositorySnapshot, SnapshotId,
    SourceRange, SymbolIdentity, SymbolKind, SymbolRevision,
};

fn file(identity: FileIdentity, path: &str, content: &str) -> FileRevision {
    FileRevision {
        identity,
        path: RepoPath::new(path).expect("valid path"),
        content_digest: ContentDigest::from_bytes(*blake3::hash(content.as_bytes()).as_bytes()),
        content: content.as_bytes().to_vec(),
        language: Language::Go,
    }
}

fn symbol(
    identity: SymbolIdentity,
    file: FileIdentity,
    qualified_name: &str,
    display_name: &str,
    declaration: SourceRange,
    kind: SymbolKind,
    continues: bool,
) -> SymbolRevision {
    SymbolRevision {
        identity,
        file,
        qualified_name: qualified_name.to_owned(),
        display_name: display_name.to_owned(),
        kind,
        declaration,
        signature: format!("func {display_name}(string) string"),
        semantic_fingerprint: None,
        continues_from: continues.then_some(identity),
        continuity_confidence: if continues { 10_000 } else { 0 },
    }
}

fn snapshot(
    id: SnapshotId,
    repository: RepositoryId,
    parent: Option<SnapshotId>,
    revision: &str,
    files: Vec<FileRevision>,
    symbols: Vec<SymbolRevision>,
    relations: Vec<CodeRelation>,
    observed_at: i64,
) -> RepositorySnapshot {
    let mut snapshot = RepositorySnapshot {
        id,
        repository,
        parent,
        revision: revision.to_owned(),
        observed_at: TimestampMicros(observed_at),
        files,
        symbols,
        relations,
        manifest_digest: ContentDigest::from_bytes([0; 32]),
    };
    snapshot.manifest_digest = CodeMemory::snapshot_manifest(&snapshot).expect("manifest");
    snapshot
}

#[test]
fn go_symbol_survives_rename_move_and_supports_current_historical_queries() {
    let repository = RepositoryId::new();
    let first_snapshot = SnapshotId::new();
    let second_snapshot = SnapshotId::new();
    let auth_file = FileIdentity::new();
    let moved_file = FileIdentity::new();
    let test_file = FileIdentity::new();
    let hash_symbol = SymbolIdentity::new();
    let caller_symbol = SymbolIdentity::new();
    let test_symbol = SymbolIdentity::new();
    let mut memory = CodeMemory::new();
    memory
        .register_repository(RepositoryDescriptor {
            id: repository,
            name: "Rift".to_owned(),
            origin: Some("https://example.invalid/rift.git".to_owned()),
        })
        .expect("repository");

    let first = snapshot(
        first_snapshot,
        repository,
        None,
        "commit-bcrypt",
        vec![file(
            auth_file,
            "auth/password.go",
            "package auth\nfunc HashPassword(v string) string { return bcrypt(v) }\n",
        )],
        vec![symbol(
            hash_symbol,
            auth_file,
            "rift/auth.HashPassword",
            "HashPassword",
            SourceRange::new(2, 0, 2, 55).expect("range"),
            SymbolKind::Function,
            false,
        )],
        Vec::new(),
        1,
    );
    memory.ingest_snapshot(first).expect("first snapshot");

    let second = snapshot(
        second_snapshot,
        repository,
        Some(first_snapshot),
        "commit-argon2id",
        vec![
            file(
                moved_file,
                "internal/auth/password.go",
                "package auth\nfunc DerivePassword(v string) string { return argon2id(v) }\nfunc Login(v string) string { return DerivePassword(v) }\n",
            ),
            file(
                test_file,
                "internal/auth/password_test.go",
                "package auth\nfunc TestDerivePassword(t *testing.T) { DerivePassword(\"x\") }\n",
            ),
        ],
        vec![
            symbol(
                hash_symbol,
                moved_file,
                "rift/internal/auth.DerivePassword",
                "DerivePassword",
                SourceRange::new(2, 0, 2, 59).expect("range"),
                SymbolKind::Function,
                true,
            ),
            symbol(
                caller_symbol,
                moved_file,
                "rift/internal/auth.Login",
                "Login",
                SourceRange::new(3, 0, 3, 56).expect("range"),
                SymbolKind::Function,
                false,
            ),
            symbol(
                test_symbol,
                test_file,
                "rift/internal/auth.TestDerivePassword",
                "TestDerivePassword",
                SourceRange::new(2, 0, 2, 61).expect("range"),
                SymbolKind::Test,
                false,
            ),
        ],
        vec![
            CodeRelation {
                source: caller_symbol,
                target: hash_symbol,
                kind: CodeRelationKind::Calls,
                evidence_range: Some(SourceRange::new(3, 37, 3, 54).expect("range")),
            },
            CodeRelation {
                source: hash_symbol,
                target: test_symbol,
                kind: CodeRelationKind::TestedBy,
                evidence_range: None,
            },
        ],
        2,
    );
    let projection = CodeDomainProjection::from_snapshot(&second).expect("domain projection");
    projection.verify().expect("verify domain projection");
    assert_eq!(projection.records.len(), 7);
    assert!(projection.records.iter().all(|record| matches!(
        record.universal_node_type(),
        contextdb_core::NodeType::Domain { ref pack, .. } if pack == "contextdb-domain-code"
    )));
    let mut tampered_projection = projection;
    tampered_projection.records[0].payload["tampered"] = serde_json::json!(true);
    assert!(tampered_projection.verify().is_err());
    memory.ingest_snapshot(second).expect("second snapshot");
    let evidence = EvidenceId::new();
    memory
        .add_decision(DecisionRecord {
            id: DecisionId::new(),
            repository,
            title: "Password KDF parameters".to_owned(),
            rationale: "Argon2id parameters follow the measured interactive-login budget."
                .to_owned(),
            affected_symbols: BTreeSet::from([hash_symbol]),
            evidence: BTreeSet::from([evidence]),
            effective_snapshot: second_snapshot,
            superseded_at: None,
        })
        .expect("decision");
    memory
        .add_ci_run(CiRun {
            id: CiRunId::new(),
            snapshot: second_snapshot,
            passed: true,
            tests: BTreeSet::from([test_symbol]),
            evidence: BTreeSet::from([EvidenceId::new()]),
        })
        .expect("CI run");

    let current = memory
        .query(
            repository,
            &CodeQuery {
                symbol: "DerivePassword".to_owned(),
                at_snapshot: None,
                include_rationale: true,
                include_impact: true,
                max_relation_visits: 32,
            },
        )
        .expect("current query");
    assert_eq!(current.location.symbol, hash_symbol);
    assert_eq!(current.location.path.as_str(), "internal/auth/password.go");
    assert_eq!(current.history.len(), 2);
    assert_eq!(current.history[0].qualified_name, "rift/auth.HashPassword");
    let impact = current.impact.as_ref().expect("impact");
    assert!(impact.affected_symbols.contains(&caller_symbol));
    assert!(impact.tests.contains(&test_symbol));
    assert!(matches!(
        current.rationale,
        RationaleResult::Supported { .. }
    ));
    assert_eq!(current.location.revision, "commit-argon2id");
    let hierarchy = memory
        .hierarchy(repository, None)
        .expect("repository hierarchy");
    assert_eq!(hierarchy.files.len(), 2);
    assert!(
        hierarchy.files[&RepoPath::new("internal/auth/password.go").expect("path")]
            .contains(&hash_symbol)
    );
    let preflight = memory
        .preflight(repository, "DerivePassword", 32)
        .expect("preflight");
    assert_eq!(preflight.latest_ci_passed, Some(true));
    assert!(!preflight.missing_test_execution_evidence);
    assert!(!preflight.ci_evidence.is_empty());

    let historical = memory
        .query(
            repository,
            &CodeQuery {
                symbol: "HashPassword".to_owned(),
                at_snapshot: Some(first_snapshot),
                include_rationale: true,
                include_impact: false,
                max_relation_visits: 1,
            },
        )
        .expect("historical query");
    assert_eq!(historical.location.path.as_str(), "auth/password.go");
    assert!(matches!(historical.rationale, RationaleResult::Unknown));

    let portable = memory.export_portable().expect("portable archive");
    let restored = CodeMemory::from_portable(&portable).expect("restore archive");
    assert_eq!(
        restored
            .query(
                repository,
                &CodeQuery {
                    symbol: "DerivePassword".to_owned(),
                    at_snapshot: None,
                    include_rationale: true,
                    include_impact: true,
                    max_relation_visits: 32,
                },
            )
            .expect("restored query"),
        current
    );
}

#[test]
fn invalid_paths_digests_continuity_and_portable_tampering_fail_closed() {
    assert!(RepoPath::new("../secret.txt").is_err());
    assert!(RepoPath::new("C:/absolute.txt").is_err());
    assert!(SourceRange::new(2, 4, 2, 4).is_err());

    let repository = RepositoryId::new();
    let id = SnapshotId::new();
    let file_id = FileIdentity::new();
    let symbol_id = SymbolIdentity::new();
    let mut memory = CodeMemory::new();
    memory
        .register_repository(RepositoryDescriptor {
            id: repository,
            name: "fixture".to_owned(),
            origin: None,
        })
        .expect("repository");
    let mut bad = snapshot(
        id,
        repository,
        None,
        "one",
        vec![file(file_id, "main.go", "package main\nfunc main() {}\n")],
        vec![symbol(
            symbol_id,
            file_id,
            "main.main",
            "main",
            SourceRange::new(2, 0, 2, 14).expect("range"),
            SymbolKind::Function,
            false,
        )],
        Vec::new(),
        1,
    );
    bad.files[0].content[0] ^= 1;
    bad.manifest_digest = CodeMemory::snapshot_manifest(&bad).expect("manifest");
    assert!(memory.ingest_snapshot(bad).is_err());

    let good = snapshot(
        id,
        repository,
        None,
        "one",
        vec![file(file_id, "main.go", "package main\nfunc main() {}\n")],
        vec![symbol(
            symbol_id,
            file_id,
            "main.main",
            "main",
            SourceRange::new(2, 0, 2, 14).expect("range"),
            SymbolKind::Function,
            false,
        )],
        Vec::new(),
        1,
    );
    memory.ingest_snapshot(good).expect("valid snapshot");
    let mut portable: PortableCodeMemory = memory.export_portable().expect("portable");
    portable.payload[0] ^= 1;
    assert!(CodeMemory::from_portable(&portable).is_err());
}

#[test]
fn compiler_native_go_index_preserves_identity_across_symbol_rename_and_file_move() {
    let repository = RepositoryId::new();
    let fingerprint = "ab".repeat(32);
    let first_index = GoCompilerIndex {
        schema_version: 1,
        module: "example.dev/rift".to_owned(),
        package: "example.dev/rift/auth".to_owned(),
        files: vec![GoSourceFile {
            path: "auth/password.go".to_owned(),
            content: "package auth\nfunc HashPassword(v string) string { return kdf(v) }\n"
                .to_owned(),
        }],
        symbols: vec![GoIndexSymbol {
            key: "example.dev/rift/auth.HashPassword".to_owned(),
            qualified_name: "example.dev/rift/auth.HashPassword".to_owned(),
            display_name: "HashPassword".to_owned(),
            kind: "function".to_owned(),
            file: "auth/password.go".to_owned(),
            range: SourceRange::new(2, 0, 2, 52).expect("range"),
            signature: "func(v string) string".to_owned(),
            semantic_fingerprint: fingerprint.clone(),
        }],
        relations: Vec::new(),
    };
    let first = GoSnapshotAdapter::build(
        repository,
        SnapshotId::new(),
        None,
        "old",
        TimestampMicros(1),
        &first_index,
    )
    .expect("first compiler snapshot");
    let identity = first.symbols[0].identity;
    let second_index = GoCompilerIndex {
        schema_version: 1,
        module: "example.dev/rift".to_owned(),
        package: "example.dev/rift/internal/auth".to_owned(),
        files: vec![GoSourceFile {
            path: "internal/auth/password.go".to_owned(),
            content: "package auth\nfunc DerivePassword(v string) string { return kdf(v) }\n"
                .to_owned(),
        }],
        symbols: vec![GoIndexSymbol {
            key: "example.dev/rift/internal/auth.DerivePassword".to_owned(),
            qualified_name: "example.dev/rift/internal/auth.DerivePassword".to_owned(),
            display_name: "DerivePassword".to_owned(),
            kind: "function".to_owned(),
            file: "internal/auth/password.go".to_owned(),
            range: SourceRange::new(2, 0, 2, 54).expect("range"),
            signature: "func(v string) string".to_owned(),
            semantic_fingerprint: fingerprint,
        }],
        relations: Vec::new(),
    };
    let second = GoSnapshotAdapter::build(
        repository,
        SnapshotId::new(),
        Some(&first),
        "new",
        TimestampMicros(2),
        &second_index,
    )
    .expect("second compiler snapshot");
    assert_eq!(second.symbols[0].identity, identity);
    assert_eq!(second.symbols[0].continues_from, Some(identity));
    assert_eq!(second.symbols[0].continuity_confidence, 10_000);
    assert_ne!(second.files[0].identity, first.files[0].identity);

    let encoded = serde_json::to_vec(&second_index).expect("strict JSON");
    assert_eq!(
        GoCompilerIndex::from_json(&encoded).expect("parse helper output"),
        second_index
    );
    let mut unknown_field: serde_json::Value =
        serde_json::from_slice(&encoded).expect("JSON value");
    unknown_field["provider_json"] = serde_json::json!({"must": "not enter"});
    assert!(
        GoCompilerIndex::from_json(
            &serde_json::to_vec(&unknown_field).expect("unknown-field JSON")
        )
        .is_err()
    );
}

#[test]
fn git_adapter_parses_rename_copy_and_content_minimized_commit_evidence() {
    let commit = GitCommitDescriptor::from_name_status_z(
        "1".repeat(40),
        vec!["2".repeat(40)],
        TimestampMicros(10),
        b"move password implementation",
        b"R094\0auth/password.go\0internal/auth/password.go\0M\0go.mod\0C100\0old_test.go\0new_test.go\0",
    )
    .expect("Git descriptor");
    assert_eq!(commit.changes.len(), 3);
    let rename = commit
        .changes
        .iter()
        .find(|change| change.kind == GitChangeKind::Renamed)
        .expect("rename");
    assert_eq!(rename.similarity, Some(94));
    assert_eq!(
        rename.new_path.as_ref().expect("new path").as_str(),
        "internal/auth/password.go"
    );
    assert!(
        !commit
            .message_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(
        GitCommitDescriptor::from_name_status_z(
            "NOT-A-GIT-OID",
            Vec::new(),
            TimestampMicros(0),
            b"bad",
            b"A\0../escape\0"
        )
        .is_err()
    );
}
