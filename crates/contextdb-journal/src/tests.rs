#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures use immediate failure semantics"
)]

use std::collections::BTreeSet;
use std::path::Path;

use contextdb_core::{
    AccessCapability, ActorId, Audience, AudienceGrant, CommitSeq, ConsentPolicy, ContentBlockId,
    ContentDigest, DerivationId, DerivationKind, DerivationRef, DerivedWorkItem, EpistemicRole,
    HierarchyViewId, LineageNode, MaintenanceMutationSet, MaintenanceOperation, MemorySpaceId,
    MemorySubjectId, MemoryUsePolicy, ModificationPolicy, MutationId, NodeId, NonEmptyVec,
    ObservationId, ObservationUnit, OwnershipPolicy, Perspective, PipelineIdentity, PolicyDecision,
    PolicyId, Purpose, RetentionPolicy, ScopeId, ScopeInheritance, ScopeKind, ScopeRef,
    SecurityClassification, SecurityPolicy, SemanticEnvelope, SemanticMutationSet, SnapshotRef,
    SourceId, TimeRange, TimestampMicros, WorkspaceId,
};
use contextdb_format::{RecordEnvelope, RecordKind};
use contextdb_storage::{
    CheckpointManifest, CommitReceipt, CompactReport, CompactRequest, Durability, Entry, Keyspace,
    ReadSnapshot, SnapshotSelector, StorageEngine, StorageSequence, VerifyMode, VerifyReport,
    WriteTransaction,
};
use contextdb_storage_fault::{FaultAction, FaultStorage};
use contextdb_storage_memory::{MemorySnapshot, MemoryStorage, MemoryTransaction};
use contextdb_storage_redb::RedbStorage;

use crate::key::{EVENT_PREFIX, event_key, mutation_key, outbox_key};
use crate::{
    CommitOptions, CommitStage, IdempotencyKey, JournalCoordinator, JournalError, JournalEvent,
    JournalSnapshotSelector, PortableJournalBackup, ValidatedMaintenanceBytes,
    ValidatedMutationBytes, ValidatedObservationBytes,
};

fn envelope() -> SemanticEnvelope {
    let owner = MemorySubjectId::new();
    let narrator = ActorId::new();
    let purposes = BTreeSet::from([Purpose::KnowledgeRecall]);
    SemanticEnvelope {
        scopes: NonEmptyVec::new(ScopeRef {
            kind: ScopeKind::Workspace,
            id: ScopeId::new(),
            inheritance: ScopeInheritance::Exact,
        }),
        perspective: Perspective {
            knower: owner,
            experiencer: Some(owner),
            narrator,
            role: EpistemicRole::Asserter,
        },
        ownership: OwnershipPolicy {
            owners: NonEmptyVec::new(owner),
            audience_grants: vec![AudienceGrant {
                audience: Audience::Owner,
                purposes: purposes.clone(),
                capabilities: BTreeSet::from([AccessCapability::Retrieve]),
            }],
            allowed_purposes: purposes,
            modification: ModificationPolicy {
                owners_may_modify: true,
                delegates_may_modify: false,
                system_may_derive: true,
            },
        },
        consent: ConsentPolicy {
            required: false,
            decisions: Vec::new(),
        },
        use_policy: MemoryUsePolicy {
            retrieve: PolicyDecision::Allow,
            influence_response: PolicyDecision::Allow,
            mention_explicitly: PolicyDecision::Allow,
            external_model_use: PolicyDecision::Deny,
            retention: RetentionPolicy::Indefinite,
        },
        security: SecurityPolicy {
            classification: SecurityClassification::Internal,
            labels: BTreeSet::new(),
            required_compartments: BTreeSet::new(),
            allow_external_processing: false,
        },
        derivation: DerivationRef {
            id: DerivationId::new(),
            kind: DerivationKind::ActorAssertion,
            actor: Some(narrator),
            model_call: None,
            pipeline: PipelineIdentity {
                name: "journal-test".to_owned(),
                version: "1".to_owned(),
                schema_version: "1".to_owned(),
            },
            inputs: vec![LineageNode::External {
                namespace: "fixture".to_owned(),
                identifier: "observation".to_owned(),
            }],
        },
    }
}

fn observation() -> ObservationUnit {
    let envelope = envelope();
    ObservationUnit {
        id: ObservationId::new(),
        workspace_id: WorkspaceId::new(),
        memory_spaces: NonEmptyVec::new(MemorySpaceId::new()),
        source_id: SourceId::new(),
        stream_position: None,
        participants: NonEmptyVec::new(envelope.perspective.narrator),
        occurred_at: TimeRange::open_ended(TimestampMicros(10)),
        observed_at: TimestampMicros(11),
        recorded_at: TimestampMicros(12),
        artifact_refs: Vec::new(),
        content_block_refs: vec![ContentBlockId::new()],
        content_hash: ContentDigest::from_bytes([7; 32]),
        envelope,
    }
}

fn exact_observation(value: &ObservationUnit) -> ValidatedObservationBytes {
    let mut bytes = serde_json::to_vec_pretty(value).expect("serialize observation");
    bytes.push(b'\n');
    ValidatedObservationBytes::from_json(bytes).expect("valid observation")
}

fn mutation(
    base: CommitSeq,
    observation_id: ObservationId,
    work: Vec<DerivedWorkItem>,
) -> ValidatedMutationBytes {
    let value = SemanticMutationSet {
        id: MutationId::new(),
        base_snapshot: SnapshotRef { commit_seq: base },
        journal_refs: NonEmptyVec::new(observation_id),
        observation_appends: Vec::new(),
        episode_view_writes: Vec::new(),
        node_creates: Vec::new(),
        node_revisions: Vec::new(),
        claim_creates: Vec::new(),
        claim_revisions: Vec::new(),
        edge_creates: Vec::new(),
        edge_revisions: Vec::new(),
        conflict_creates: Vec::new(),
        conflict_revisions: Vec::new(),
        candidate_writes: Vec::new(),
        typed_memory_writes: Vec::new(),
        derived_work: work,
    };
    let mut bytes = serde_json::to_vec_pretty(&value).expect("serialize mutation");
    bytes.push(b'\n');
    ValidatedMutationBytes::from_json(bytes).expect("valid mutation")
}

fn maintenance(base: CommitSeq, operation: MaintenanceOperation) -> ValidatedMaintenanceBytes {
    let value = MaintenanceMutationSet {
        id: MutationId::new(),
        base_snapshot: SnapshotRef { commit_seq: base },
        operation,
        derived_work: vec![DerivedWorkItem::DirtyHierarchyRegion {
            roots: vec![NodeId::new()],
        }],
    };
    let mut bytes = serde_json::to_vec_pretty(&value).expect("serialize maintenance mutation");
    bytes.push(b'\n');
    ValidatedMaintenanceBytes::from_json(bytes).expect("valid maintenance mutation")
}

fn key(value: &str) -> IdempotencyKey {
    IdempotencyKey::new(value).expect("valid idempotency key")
}

#[test]
fn observation_and_publication_are_distinct_ordered_frames_with_atomic_outbox() {
    let storage = MemoryStorage::new();
    let journal = JournalCoordinator::new(storage).expect("open journal");
    let observation = observation();
    let accepted = exact_observation(&observation);
    let observation_receipt = journal
        .accept_observation(&key("observation-1"), &accepted, CommitOptions::default())
        .expect("accept observation");
    assert_eq!(observation_receipt.commit_seq, CommitSeq::new(1));
    assert_eq!(observation_receipt.durability, Durability::Sync);

    let work = vec![
        DerivedWorkItem::UpdateSessionActiveSet {
            observations: vec![observation.id],
        },
        DerivedWorkItem::Vectorize {
            nodes: vec![NodeId::new()],
        },
    ];
    let mutation = mutation(CommitSeq::new(1), observation.id, work.clone());
    let publication = journal
        .publish_semantic(&key("publication-1"), &mutation, CommitOptions::default())
        .expect("publish semantic mutation");
    assert_eq!(publication.commit_seq, CommitSeq::new(2));
    assert_eq!(publication.outbox_count, 2);

    let snapshot = journal
        .snapshot(JournalSnapshotSelector::Latest)
        .expect("materialize latest snapshot");
    assert_eq!(snapshot.commit_seq, CommitSeq::new(2));
    assert_eq!(snapshot.events.len(), 2);
    match &snapshot.events[0] {
        JournalEvent::ObservationAccepted {
            commit_seq,
            exact_bytes,
            ..
        } => {
            assert_eq!(*commit_seq, CommitSeq::new(1));
            assert_eq!(exact_bytes, accepted.exact_bytes());
        }
        JournalEvent::SemanticPublished { .. } | JournalEvent::MaintenancePublished { .. } => {
            panic!("wrong first frame kind")
        }
    }
    match &snapshot.events[1] {
        JournalEvent::SemanticPublished {
            commit_seq,
            exact_mutation_bytes,
            outbox,
            ..
        } => {
            assert_eq!(*commit_seq, CommitSeq::new(2));
            assert_eq!(exact_mutation_bytes, mutation.exact_bytes());
            assert_eq!(outbox, &work);
        }
        JournalEvent::ObservationAccepted { .. } | JournalEvent::MaintenancePublished { .. } => {
            panic!("wrong second frame kind")
        }
    }

    let replay = journal
        .replay_mutations(JournalSnapshotSelector::Latest)
        .expect("replay mutations");
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].exact_bytes, mutation.exact_bytes());
    let historical = journal
        .snapshot(JournalSnapshotSelector::At(CommitSeq::new(1)))
        .expect("logical historical prefix");
    assert_eq!(historical.events.len(), 1);

    let verified = journal.verify(VerifyMode::Deep).expect("deep verify");
    assert_eq!(verified.events, 2);
    assert_eq!(verified.outbox_records, 2);
    assert_eq!(verified.idempotency_records, 2);
}

#[test]
fn lost_sync_response_is_recovered_by_idempotent_retry_without_logical_duplication() {
    let storage = MemoryStorage::new();
    let journal = JournalCoordinator::new(storage).expect("open journal");
    let accepted = exact_observation(&observation());
    let first = journal.accept_observation(
        &key("lost-response"),
        &accepted,
        CommitOptions {
            durability: Durability::Sync,
            fail_at: Some(CommitStage::AfterCommitBeforeAck),
        },
    );
    assert!(matches!(
        first,
        Err(JournalError::LostResponse {
            commit_seq
        }) if commit_seq == CommitSeq::new(1)
    ));

    let retry = journal
        .accept_observation(&key("lost-response"), &accepted, CommitOptions::default())
        .expect("reconstruct durable receipt");
    assert!(retry.replayed);
    assert_eq!(retry.commit_seq, CommitSeq::new(1));
    assert_eq!(retry.durability, Durability::Sync);
    assert_eq!(
        journal
            .snapshot(JournalSnapshotSelector::Latest)
            .expect("snapshot")
            .events
            .len(),
        1
    );
}

#[test]
fn storage_enospc_is_atomic_and_storage_level_response_loss_is_retryable() {
    let (storage, faults) = FaultStorage::new(MemoryStorage::new());
    let journal = JournalCoordinator::new(storage).expect("open fault-injected journal");
    let accepted = exact_observation(&observation());

    faults
        .arm(FaultAction::NoSpaceBeforeCommit)
        .expect("arm no-space fault");
    assert!(matches!(
        journal.accept_observation(
            &key("enospc-observation"),
            &accepted,
            CommitOptions::default()
        ),
        Err(JournalError::Storage(_))
    ));
    assert_eq!(
        journal
            .snapshot(JournalSnapshotSelector::Latest)
            .expect("snapshot after rejected commit")
            .commit_seq,
        CommitSeq::GENESIS
    );
    let accepted_receipt = journal
        .accept_observation(
            &key("enospc-observation"),
            &accepted,
            CommitOptions::default(),
        )
        .expect("retry after capacity returns");
    assert_eq!(accepted_receipt.commit_seq, CommitSeq::new(1));

    let mutation = mutation(CommitSeq::new(1), accepted.observation_id(), Vec::new());
    faults
        .arm(FaultAction::LoseResponseAfterCommit)
        .expect("arm storage-level response loss");
    assert!(matches!(
        journal.publish_semantic(
            &key("storage-lost-response"),
            &mutation,
            CommitOptions::default()
        ),
        Err(JournalError::Storage(_))
    ));
    let recovered = journal
        .publish_semantic(
            &key("storage-lost-response"),
            &mutation,
            CommitOptions::default(),
        )
        .expect("recover committed receipt from durable idempotency record");
    assert!(recovered.replayed);
    assert_eq!(recovered.commit_seq, CommitSeq::new(2));
    assert_eq!(
        journal
            .snapshot(JournalSnapshotSelector::Latest)
            .expect("snapshot after recovered response")
            .events
            .len(),
        2
    );
}

#[test]
fn idempotency_digest_conflicts_and_duplicate_observation_ids_fail_closed() {
    let journal = JournalCoordinator::new(MemoryStorage::new()).expect("open journal");
    let first = observation();
    let accepted = exact_observation(&first);
    journal
        .accept_observation(&key("stable-key"), &accepted, CommitOptions::default())
        .expect("first acceptance");
    let replay = journal
        .accept_observation(&key("stable-key"), &accepted, CommitOptions::default())
        .expect("idempotent replay");
    assert!(replay.replayed);

    let different = exact_observation(&observation());
    assert!(matches!(
        journal.accept_observation(&key("stable-key"), &different, CommitOptions::default()),
        Err(JournalError::IdempotencyConflict)
    ));
    assert!(matches!(
        journal.accept_observation(&key("different-key"), &accepted, CommitOptions::default()),
        Err(JournalError::DuplicateObservation)
    ));
}

#[test]
fn precommit_failpoints_rollback_every_staged_frame() {
    for stage in [CommitStage::AfterValidation, CommitStage::AfterStaging] {
        let journal = JournalCoordinator::new(MemoryStorage::new()).expect("open journal");
        let accepted = exact_observation(&observation());
        assert!(matches!(
            journal.accept_observation(
                &key("failpoint"),
                &accepted,
                CommitOptions {
                    durability: Durability::Sync,
                    fail_at: Some(stage),
                },
            ),
            Err(JournalError::InjectedFailure(actual)) if actual == stage
        ));
        let snapshot = journal
            .snapshot(JournalSnapshotSelector::Latest)
            .expect("empty snapshot");
        assert_eq!(snapshot.commit_seq, CommitSeq::GENESIS);
        assert!(snapshot.events.is_empty());
    }
}

#[test]
fn semantic_publication_rejects_stale_base_and_unknown_observation() {
    let journal = JournalCoordinator::new(MemoryStorage::new()).expect("open journal");
    let observation = observation();
    journal
        .accept_observation(
            &key("observation"),
            &exact_observation(&observation),
            CommitOptions::default(),
        )
        .expect("accept observation");

    let stale = mutation(CommitSeq::GENESIS, observation.id, Vec::new());
    assert!(matches!(
        journal.publish_semantic(&key("stale"), &stale, CommitOptions::default()),
        Err(JournalError::BaseSnapshotMismatch { .. })
    ));
    let unknown = mutation(CommitSeq::new(1), ObservationId::new(), Vec::new());
    assert!(matches!(
        journal.publish_semantic(&key("missing"), &unknown, CommitOptions::default()),
        Err(JournalError::MissingObservation(_))
    ));
}

#[test]
fn maintenance_and_policy_transactions_are_atomic_idempotent_and_replayable() {
    let journal = JournalCoordinator::new(MemoryStorage::new()).expect("open journal");
    let accepted = exact_observation(&observation());
    journal
        .accept_observation(
            &key("maintenance-seed"),
            &accepted,
            CommitOptions::default(),
        )
        .expect("seed logical head");

    let hierarchy = maintenance(
        CommitSeq::new(1),
        MaintenanceOperation::HierarchyPublication {
            view_id: HierarchyViewId::new(),
            generation: 1,
            manifest_digest: ContentDigest::from_bytes([3; 32]),
        },
    );
    let lost = journal.publish_maintenance(
        &key("hierarchy-publish"),
        &hierarchy,
        CommitOptions {
            durability: Durability::Sync,
            fail_at: Some(CommitStage::AfterCommitBeforeAck),
        },
    );
    assert!(matches!(
        lost,
        Err(JournalError::LostResponse { commit_seq }) if commit_seq == CommitSeq::new(2)
    ));
    let hierarchy_receipt = journal
        .publish_maintenance(
            &key("hierarchy-publish"),
            &hierarchy,
            CommitOptions::default(),
        )
        .expect("recover maintenance receipt");
    assert!(hierarchy_receipt.replayed);
    assert_eq!(hierarchy_receipt.outbox_count, 1);

    let policy = maintenance(
        CommitSeq::new(2),
        MaintenanceOperation::PolicyRevision {
            policy_id: PolicyId::new(),
            target: LineageNode::External {
                namespace: "workspace-policy".to_owned(),
                identifier: "default".to_owned(),
            },
            envelope: Box::new(envelope()),
        },
    );
    let policy_receipt = journal
        .publish_maintenance(&key("policy-publish"), &policy, CommitOptions::default())
        .expect("publish policy revision");
    assert_eq!(policy_receipt.commit_seq, CommitSeq::new(3));

    let snapshot = journal
        .snapshot(JournalSnapshotSelector::Latest)
        .expect("maintenance snapshot");
    assert_eq!(snapshot.commit_seq, CommitSeq::new(3));
    assert!(matches!(
        &snapshot.events[1],
        JournalEvent::MaintenancePublished {
            exact_mutation_bytes,
            ..
        } if exact_mutation_bytes == hierarchy.exact_bytes()
    ));
    assert!(matches!(
        &snapshot.events[2],
        JournalEvent::MaintenancePublished {
            exact_mutation_bytes,
            ..
        } if exact_mutation_bytes == policy.exact_bytes()
    ));
    let replay = journal
        .replay_maintenance(JournalSnapshotSelector::Latest)
        .expect("replay maintenance");
    assert_eq!(replay.len(), 2);
    assert_eq!(replay[0].exact_bytes, hierarchy.exact_bytes());
    assert_eq!(replay[1].exact_bytes, policy.exact_bytes());
    assert!(
        journal
            .replay_mutations(JournalSnapshotSelector::Latest)
            .expect("semantic-only replay")
            .is_empty()
    );
    let verified = journal
        .verify(VerifyMode::Deep)
        .expect("verify maintenance");
    assert_eq!(verified.events, 3);
    assert_eq!(verified.outbox_records, 2);

    let stale = maintenance(
        CommitSeq::new(1),
        MaintenanceOperation::HierarchyPublication {
            view_id: HierarchyViewId::new(),
            generation: 1,
            manifest_digest: ContentDigest::from_bytes([4; 32]),
        },
    );
    assert!(matches!(
        journal.publish_maintenance(&key("stale-maintenance"), &stale, CommitOptions::default()),
        Err(JournalError::BaseSnapshotMismatch { .. })
    ));
}

#[test]
fn semantic_failpoint_never_exposes_partial_mutation_or_outbox_and_lost_response_retries() {
    let storage = MemoryStorage::new();
    let journal = JournalCoordinator::new(storage.clone()).expect("open journal");
    let observation = observation();
    journal
        .accept_observation(
            &key("observation"),
            &exact_observation(&observation),
            CommitOptions::default(),
        )
        .expect("accept observation");
    let mutation = mutation(
        CommitSeq::new(1),
        observation.id,
        vec![DerivedWorkItem::UpdateSessionActiveSet {
            observations: vec![observation.id],
        }],
    );

    assert!(matches!(
        journal.publish_semantic(
            &key("staged-publication"),
            &mutation,
            CommitOptions {
                durability: Durability::Sync,
                fail_at: Some(CommitStage::AfterStaging),
            }
        ),
        Err(JournalError::InjectedFailure(CommitStage::AfterStaging))
    ));
    let after_rollback = journal
        .snapshot(JournalSnapshotSelector::Latest)
        .expect("snapshot after rollback");
    assert_eq!(after_rollback.commit_seq, CommitSeq::new(1));
    assert_eq!(after_rollback.events.len(), 1);
    let physical = storage
        .begin_read(SnapshotSelector::Latest)
        .expect("physical snapshot");
    assert!(
        physical
            .scan_prefix(
                &Keyspace::new("journal_outbox").expect("outbox keyspace"),
                b"o"
            )
            .expect("scan outbox")
            .is_empty()
    );
    assert!(
        physical
            .scan_prefix(
                &Keyspace::new("journal_mutation").expect("mutation keyspace"),
                b"m"
            )
            .expect("scan mutations")
            .is_empty()
    );
    drop(physical);

    let lost = journal.publish_semantic(
        &key("lost-publication"),
        &mutation,
        CommitOptions {
            durability: Durability::Sync,
            fail_at: Some(CommitStage::AfterCommitBeforeAck),
        },
    );
    assert!(matches!(
        lost,
        Err(JournalError::LostResponse { commit_seq })
            if commit_seq == CommitSeq::new(2)
    ));
    let retry = journal
        .publish_semantic(
            &key("lost-publication"),
            &mutation,
            CommitOptions::default(),
        )
        .expect("retry publication");
    assert!(retry.replayed);
    assert_eq!(retry.commit_seq, CommitSeq::new(2));
    assert_eq!(retry.outbox_count, 1);
    let after_retry = journal
        .snapshot(JournalSnapshotSelector::Latest)
        .expect("snapshot after retry");
    assert_eq!(after_retry.events.len(), 2);
    match &after_retry.events[1] {
        JournalEvent::SemanticPublished { outbox, .. } => assert_eq!(outbox.len(), 1),
        JournalEvent::ObservationAccepted { .. } | JournalEvent::MaintenancePublished { .. } => {
            panic!("wrong event kind")
        }
    }
}

#[test]
fn portable_backup_restores_exact_frames_and_idempotency_across_backends() {
    let source = JournalCoordinator::new(MemoryStorage::new()).expect("open source journal");
    let observation = observation();
    let accepted = exact_observation(&observation);
    source
        .accept_observation(
            &key("backup-observation"),
            &accepted,
            CommitOptions::default(),
        )
        .expect("accept source observation");
    let mutation = mutation(
        CommitSeq::new(1),
        observation.id,
        vec![DerivedWorkItem::UpdateSessionActiveSet {
            observations: vec![observation.id],
        }],
    );
    source
        .publish_semantic(
            &key("backup-publication"),
            &mutation,
            CommitOptions::default(),
        )
        .expect("publish source mutation");
    let expected = source
        .snapshot(JournalSnapshotSelector::Latest)
        .expect("source snapshot");
    let backup = source.create_backup().expect("create portable backup");
    assert_eq!(backup.commit_seq, CommitSeq::new(2));
    assert!(backup.records >= 8);

    let (restored, report) = JournalCoordinator::restore_backup(MemoryStorage::new(), &backup)
        .expect("restore into memory backend");
    assert_eq!(report.commit_seq, CommitSeq::new(2));
    assert_eq!(report.records, backup.records);
    assert_eq!(report.payload_digest, backup.payload_digest);
    let restored_snapshot = restored
        .snapshot(JournalSnapshotSelector::Latest)
        .expect("restored snapshot");
    assert_eq!(restored_snapshot.commit_seq, expected.commit_seq);
    assert_eq!(restored_snapshot.events, expected.events);
    assert!(
        restored
            .accept_observation(
                &key("backup-observation"),
                &accepted,
                CommitOptions::default()
            )
            .expect("restored observation retry")
            .replayed
    );
    assert!(
        restored
            .publish_semantic(
                &key("backup-publication"),
                &mutation,
                CommitOptions::default()
            )
            .expect("restored publication retry")
            .replayed
    );

    let directory = tempfile::tempdir().expect("temporary restore directory");
    let path = directory.path().join("restored.redb");
    let redb = RedbStorage::open(&path).expect("open redb restore target");
    let (restored_redb, _) =
        JournalCoordinator::restore_backup(redb, &backup).expect("restore into redb backend");
    let redb_snapshot = restored_redb
        .snapshot(JournalSnapshotSelector::Latest)
        .expect("redb restored snapshot");
    assert_eq!(redb_snapshot.commit_seq, expected.commit_seq);
    assert_eq!(redb_snapshot.events, expected.events);
    drop(restored_redb);
    let reopened = JournalCoordinator::new(RedbStorage::open(&path).expect("reopen redb"))
        .expect("recover restored redb journal");
    let reopened_snapshot = reopened
        .snapshot(JournalSnapshotSelector::Latest)
        .expect("reopened redb snapshot");
    assert_eq!(reopened_snapshot.commit_seq, expected.commit_seq);
    assert_eq!(reopened_snapshot.events, expected.events);
}

#[test]
fn portable_backup_tampering_and_nonempty_restore_fail_closed() {
    let source = JournalCoordinator::new(MemoryStorage::new()).expect("open source journal");
    let accepted = exact_observation(&observation());
    source
        .accept_observation(&key("backup-source"), &accepted, CommitOptions::default())
        .expect("seed backup");
    let backup = source.create_backup().expect("create backup");

    let mut tampered = PortableJournalBackup {
        payload: backup.payload.clone(),
        ..backup.clone()
    };
    tampered.payload[0] ^= 1;
    assert!(matches!(
        JournalCoordinator::restore_backup(MemoryStorage::new(), &tampered),
        Err(JournalError::InvalidBackup { .. })
    ));

    let target = JournalCoordinator::new(MemoryStorage::new()).expect("open target journal");
    target
        .accept_observation(
            &key("target-existing"),
            &exact_observation(&observation()),
            CommitOptions::default(),
        )
        .expect("seed target");
    assert!(matches!(
        JournalCoordinator::restore_backup(target.into_engine(), &backup),
        Err(JournalError::RestoreTargetNotEmpty)
    ));
}

#[test]
fn portable_backup_rejects_self_consistent_unpublished_tail_without_receipt() {
    let source = JournalCoordinator::new(MemoryStorage::new()).expect("open source journal");
    source
        .accept_observation(
            &key("backup-tail-source"),
            &exact_observation(&observation()),
            CommitOptions::default(),
        )
        .expect("seed backup");
    let mut malicious = source.create_backup().expect("create backup");

    let mut payload: serde_json::Value =
        serde_json::from_slice(&malicious.payload).expect("decode private backup payload");
    let sections = payload
        .get_mut("sections")
        .and_then(serde_json::Value::as_array_mut)
        .expect("backup sections");
    let mutations = sections
        .iter_mut()
        .find(|section| {
            section.get("name").and_then(serde_json::Value::as_str) == Some("journal_mutation")
        })
        .expect("mutation section");
    mutations
        .get_mut("entries")
        .and_then(serde_json::Value::as_array_mut)
        .expect("mutation entries")
        .push(serde_json::json!({
            "key": mutation_key(MutationId::new()),
            "value": RecordEnvelope::encode(
                RecordKind::SemanticMutation,
                1,
                0,
                malicious.commit_seq.get() + 1,
                b"attacker-controlled-torn-tail"
            ).expect("encode framed malicious tail")
        }));
    malicious.records = malicious.records.checked_add(1).expect("record count");
    payload["records"] = serde_json::Value::from(malicious.records);
    malicious.payload = serde_json::to_vec(&payload).expect("encode malicious payload");
    malicious.payload_digest = *blake3::hash(&malicious.payload).as_bytes();

    let target = MemoryStorage::new();
    assert!(matches!(
        JournalCoordinator::restore_backup(target.clone(), &malicious),
        Err(JournalError::InvalidBackup { .. })
    ));
    let target_snapshot = target
        .begin_read(SnapshotSelector::Latest)
        .expect("read rejected restore target");
    assert!(
        target_snapshot
            .scan_prefix(
                &Keyspace::new("journal_mutation").expect("mutation keyspace"),
                b""
            )
            .expect("scan rejected restore target")
            .is_empty(),
        "mutation records were installed before malicious-tail rejection"
    );
}

#[test]
fn checksummed_prefix_corruption_is_detected_and_never_silently_repaired() {
    let storage = MemoryStorage::new();
    let journal = JournalCoordinator::new(storage.clone()).expect("open journal");
    journal
        .accept_observation(
            &key("observation"),
            &exact_observation(&observation()),
            CommitOptions::default(),
        )
        .expect("accept observation");
    drop(journal);

    let events = Keyspace::new("semantic_journal").expect("event keyspace");
    let snapshot = storage
        .begin_read(SnapshotSelector::Latest)
        .expect("latest snapshot");
    let mut frame = snapshot
        .get(&events, &event_key(1))
        .expect("read frame")
        .expect("event exists");
    *frame.last_mut().expect("payload byte") ^= 0x80;
    drop(snapshot);
    let mut writer = storage.begin_write().expect("writer");
    writer
        .put(&events, event_key(1), frame)
        .expect("stage corruption");
    writer
        .commit(Durability::Sync)
        .expect("commit corruption fixture");

    assert!(matches!(
        JournalCoordinator::new(storage),
        Err(JournalError::Format(_))
    ));
}

#[test]
fn corrupted_unpublished_keyed_tail_is_removed_durably() {
    let storage = MemoryStorage::new();
    let journal = JournalCoordinator::new(storage.clone()).expect("open journal");
    let events = Keyspace::new("semantic_journal").expect("event keyspace");
    let mut writer = storage.begin_write().expect("writer");
    writer
        .put(&events, event_key(1), b"torn-frame".to_vec())
        .expect("stage torn tail");
    writer
        .put(
            &Keyspace::new("journal_outbox").expect("outbox keyspace"),
            outbox_key(1, 0),
            b"partial-outbox-frame".to_vec(),
        )
        .expect("stage partial outbox tail");
    writer
        .put(
            &Keyspace::new("journal_mutation").expect("mutation keyspace"),
            mutation_key(MutationId::new()),
            RecordEnvelope::encode(RecordKind::SemanticMutation, 1, 0, 1, b"partial")
                .expect("encode staged mutation"),
        )
        .expect("stage unpublished mutation");
    writer
        .commit(Durability::Sync)
        .expect("commit tail fixture");

    let recovery = journal.recover().expect("recover journal");
    assert_eq!(recovery.removed_tail_records, 3);
    assert_eq!(recovery.commit_seq, CommitSeq::GENESIS);
    assert_eq!(recovery.warnings.len(), 1);
    let snapshot = journal
        .snapshot(JournalSnapshotSelector::Latest)
        .expect("empty recovered prefix");
    assert_eq!(snapshot.commit_seq, CommitSeq::GENESIS);
    assert!(snapshot.events.is_empty());
    let physical = storage
        .begin_read(SnapshotSelector::Latest)
        .expect("latest physical snapshot");
    assert!(
        physical
            .scan_prefix(&events, EVENT_PREFIX)
            .expect("scan events")
            .is_empty()
    );
}

#[derive(Clone, Debug, Default)]
struct WeakDurabilityStorage(MemoryStorage);

#[derive(Debug)]
struct WeakDurabilityTransaction<'a>(MemoryTransaction<'a>);

impl ReadSnapshot for WeakDurabilityTransaction<'_> {
    fn sequence(&self) -> StorageSequence {
        self.0.sequence()
    }

    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> contextdb_storage::Result<Option<Vec<u8>>> {
        self.0.get(keyspace, key)
    }

    fn scan_prefix(
        &self,
        keyspace: &Keyspace,
        prefix: &[u8],
    ) -> contextdb_storage::Result<Vec<Entry>> {
        self.0.scan_prefix(keyspace, prefix)
    }
}

impl WriteTransaction for WeakDurabilityTransaction<'_> {
    fn put(
        &mut self,
        keyspace: &Keyspace,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> contextdb_storage::Result<()> {
        self.0.put(keyspace, key, value)
    }

    fn delete(&mut self, keyspace: &Keyspace, key: Vec<u8>) -> contextdb_storage::Result<()> {
        self.0.delete(keyspace, key)
    }

    fn commit(self, durability: Durability) -> contextdb_storage::Result<CommitReceipt> {
        let mut receipt = self.0.commit(durability)?;
        receipt.durability = Durability::Ephemeral;
        Ok(receipt)
    }

    fn rollback(self) -> contextdb_storage::Result<()> {
        self.0.rollback()
    }
}

impl StorageEngine for WeakDurabilityStorage {
    type ReadSnapshot<'a>
        = MemorySnapshot
    where
        Self: 'a;
    type WriteTransaction<'a>
        = WeakDurabilityTransaction<'a>
    where
        Self: 'a;

    fn head_sequence(&self) -> contextdb_storage::Result<StorageSequence> {
        self.0.head_sequence()
    }

    fn begin_read(
        &self,
        selector: SnapshotSelector,
    ) -> contextdb_storage::Result<Self::ReadSnapshot<'_>> {
        self.0.begin_read(selector)
    }

    fn begin_write(&self) -> contextdb_storage::Result<Self::WriteTransaction<'_>> {
        self.0.begin_write().map(WeakDurabilityTransaction)
    }

    fn checkpoint(&self, target: &Path) -> contextdb_storage::Result<CheckpointManifest> {
        self.0.checkpoint(target)
    }

    fn compact(&self, request: CompactRequest) -> contextdb_storage::Result<CompactReport> {
        self.0.compact(request)
    }

    fn verify(&self, mode: VerifyMode) -> contextdb_storage::Result<VerifyReport> {
        self.0.verify(mode)
    }
}

#[test]
fn sync_is_never_acknowledged_when_backend_reports_weaker_durability() {
    let journal = JournalCoordinator::new(WeakDurabilityStorage::default()).expect("open journal");
    let accepted = exact_observation(&observation());
    let result =
        journal.accept_observation(&key("weak-durability"), &accepted, CommitOptions::default());
    assert!(matches!(
        result,
        Err(JournalError::DurabilityNotAchieved {
            requested: Durability::Sync,
            achieved: Durability::Ephemeral,
            ..
        })
    ));
    // The lying backend did publish the atomic transaction, but the coordinator
    // withheld acknowledgement and also refuses to reconstruct a Sync receipt.
    assert_eq!(
        journal
            .snapshot(JournalSnapshotSelector::Latest)
            .expect("committed logical snapshot")
            .events
            .len(),
        1
    );
    assert!(matches!(
        journal.accept_observation(&key("weak-durability"), &accepted, CommitOptions::default()),
        Err(JournalError::DurabilityNotAchieved {
            requested: Durability::Sync,
            achieved: Durability::Ephemeral,
            ..
        })
    ));
}

#[test]
fn redb_sync_commit_reopens_and_replays_exact_bytes_without_docker() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("journal.redb");
    let accepted = exact_observation(&observation());
    {
        let storage = RedbStorage::open(&path).expect("open redb");
        let journal = JournalCoordinator::new(storage).expect("open journal");
        let receipt = journal
            .accept_observation(
                &key("disk-observation"),
                &accepted,
                CommitOptions::default(),
            )
            .expect("sync disk acceptance");
        assert_eq!(receipt.durability, Durability::Sync);
    }
    {
        let storage = RedbStorage::open(&path).expect("reopen redb");
        let journal = JournalCoordinator::new(storage).expect("recover disk journal");
        let snapshot = journal
            .snapshot(JournalSnapshotSelector::Latest)
            .expect("disk snapshot");
        assert_eq!(snapshot.commit_seq, CommitSeq::new(1));
        match &snapshot.events[0] {
            JournalEvent::ObservationAccepted { exact_bytes, .. } => {
                assert_eq!(exact_bytes, accepted.exact_bytes());
            }
            JournalEvent::SemanticPublished { .. } | JournalEvent::MaintenancePublished { .. } => {
                panic!("unexpected frame kind")
            }
        }
    }
}

#[test]
fn envelope_kind_is_observation_not_semantic_publication_for_acceptance() {
    let storage = MemoryStorage::new();
    let journal = JournalCoordinator::new(storage.clone()).expect("open journal");
    journal
        .accept_observation(
            &key("kind-check"),
            &exact_observation(&observation()),
            CommitOptions::default(),
        )
        .expect("accept observation");
    let snapshot = storage
        .begin_read(SnapshotSelector::Latest)
        .expect("physical snapshot");
    let frame = snapshot
        .get(
            &Keyspace::new("semantic_journal").expect("event keyspace"),
            &event_key(1),
        )
        .expect("read")
        .expect("frame");
    let decoded = RecordEnvelope::decode(&frame).expect("checksummed envelope");
    assert_eq!(
        decoded.envelope.record_kind,
        u16::from(RecordKind::Observation)
    );
}
