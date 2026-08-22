//! Native portable journal backup, restore, recovery, and reopen scenario.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

use contextdb_core::{
    AccessCapability, ActorId, Audience, AudienceGrant, ConsentPolicy, ContentBlockId,
    ContentDigest, DerivationId, DerivationKind, DerivationRef, EpistemicRole, LineageNode,
    MemorySpaceId, MemorySubjectId, MemoryUsePolicy, ModificationPolicy, NonEmptyVec,
    ObservationId, ObservationUnit, OwnershipPolicy, Perspective, PipelineIdentity, PolicyDecision,
    Purpose, RetentionPolicy, ScopeId, ScopeInheritance, ScopeKind, ScopeRef,
    SecurityClassification, SecurityPolicy, SemanticEnvelope, SourceId, TimeRange, TimestampMicros,
    WorkspaceId,
};
use contextdb_journal::{
    CommitOptions, IdempotencyKey, JournalCoordinator, ValidatedObservationBytes,
};
use contextdb_storage::{Durability, VerifyMode};
use contextdb_storage_redb::RedbStorage;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::digest::sha256_hex;
use crate::{BenchError, Result};

/// Measurements and exact gates from one portable journal lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalOperationsOutcome {
    /// One synchronized observation latency per commit.
    pub ingest_latency_ns: Vec<u64>,
    /// Portable backup creation latency.
    pub backup_latency_ns: u64,
    /// Empty-target restore and deep verification latency.
    pub restore_latency_ns: u64,
    /// Persistent reopen, recovery, and deep verification latency.
    pub reopen_latency_ns: u64,
    /// Number of synchronized acknowledgements.
    pub synchronized_acknowledgements: u64,
    /// Final logical journal sequence.
    pub commit_seq: u64,
    /// Number of portable records.
    pub backup_records: u64,
    /// SHA-256 of the exact portable payload.
    pub backup_payload_sha256: String,
    /// Restored logical head and record counts matched the source.
    pub restore_equal: bool,
    /// Reopened logical head and event counts matched the source.
    pub reopen_equal: bool,
}

/// Runs portable backup/restore against two fresh persistent redb files.
pub fn run_journal_operations(
    observations: u64,
    seed: u64,
    source_path: &Path,
    restore_path: &Path,
) -> Result<JournalOperationsOutcome> {
    if observations == 0 {
        return Err(BenchError::InvalidConfiguration {
            field: "journal_observations",
            reason: "at least one observation is required".to_owned(),
        });
    }
    if source_path.exists() || restore_path.exists() {
        return Err(BenchError::InvalidConfiguration {
            field: "journal_paths",
            reason: "backup and restore targets must not already exist".to_owned(),
        });
    }
    let source = JournalCoordinator::new(RedbStorage::open(source_path)?)?;
    let mut ingest_latency_ns = Vec::with_capacity(
        usize::try_from(observations)
            .map_err(|_| BenchError::ArithmeticOverflow("journal observation capacity"))?,
    );
    let mut synchronized_acknowledgements = 0_u64;
    for ordinal in 0..observations {
        let observation = fixture_observation(seed, ordinal)?;
        let validated = ValidatedObservationBytes::from_observation(&observation)?;
        let idempotency = IdempotencyKey::new(format!("m17-journal-{seed:016x}-{ordinal:016x}"))?;
        let started = Instant::now();
        let receipt = source.accept_observation(
            &idempotency,
            &validated,
            CommitOptions {
                durability: Durability::Sync,
                fail_at: None,
            },
        )?;
        ingest_latency_ns.push(elapsed_ns(started)?);
        if receipt.durability == Durability::Sync && !receipt.replayed {
            synchronized_acknowledgements = synchronized_acknowledgements.saturating_add(1);
        }
    }
    let source_verified = source.verify(VerifyMode::Deep)?;
    let backup_started = Instant::now();
    let backup = source.create_backup()?;
    let backup_latency_ns = elapsed_ns(backup_started)?;
    let backup_payload_sha256 = sha256_hex(&backup.payload);

    let restore_started = Instant::now();
    let (restored, restore_report) =
        JournalCoordinator::restore_backup(RedbStorage::open(restore_path)?, &backup)?;
    let restored_verified = restored.verify(VerifyMode::Deep)?;
    let restore_latency_ns = elapsed_ns(restore_started)?;
    let restore_equal = restore_report.commit_seq == source_verified.commit_seq
        && restore_report.records == backup.records
        && restored_verified.commit_seq == source_verified.commit_seq
        && restored_verified.events == source_verified.events
        && restore_report.payload_digest == backup.payload_digest;
    drop(restored);

    let reopen_started = Instant::now();
    let reopened = JournalCoordinator::new(RedbStorage::open(restore_path)?)?;
    let reopened_verified = reopened.verify(VerifyMode::Deep)?;
    let reopen_latency_ns = elapsed_ns(reopen_started)?;
    let reopen_equal = reopened_verified.commit_seq == source_verified.commit_seq
        && reopened_verified.events == source_verified.events
        && reopened_verified.idempotency_records == source_verified.idempotency_records;

    Ok(JournalOperationsOutcome {
        ingest_latency_ns,
        backup_latency_ns,
        restore_latency_ns,
        reopen_latency_ns,
        synchronized_acknowledgements,
        commit_seq: source_verified.commit_seq.get(),
        backup_records: backup.records,
        backup_payload_sha256,
        restore_equal,
        reopen_equal,
    })
}

fn fixture_observation(seed: u64, ordinal: u64) -> Result<ObservationUnit> {
    let workspace_id = strong_id(0x01, seed, 0, WorkspaceId::from_uuid)?;
    let memory_space = strong_id(0x02, seed, 0, MemorySpaceId::from_uuid)?;
    let owner = strong_id(0x03, seed, 0, MemorySubjectId::from_uuid)?;
    let narrator = strong_id(0x04, seed, 0, ActorId::from_uuid)?;
    let source = strong_id(0x05, seed, 0, SourceId::from_uuid)?;
    let scope = strong_id(0x06, seed, 0, ScopeId::from_uuid)?;
    let observation_id = strong_id(0x07, seed, ordinal, ObservationId::from_uuid)?;
    let content_block = strong_id(0x08, seed, ordinal, ContentBlockId::from_uuid)?;
    let derivation_id = strong_id(0x09, seed, ordinal, DerivationId::from_uuid)?;
    let purposes = BTreeSet::from([Purpose::KnowledgeRecall]);
    let envelope = SemanticEnvelope {
        scopes: NonEmptyVec::new(ScopeRef {
            kind: ScopeKind::Workspace,
            id: scope,
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
            id: derivation_id,
            kind: DerivationKind::ActorAssertion,
            actor: Some(narrator),
            model_call: None,
            pipeline: PipelineIdentity {
                name: "contextdb-bench-m17".to_owned(),
                version: "1".to_owned(),
                schema_version: "1".to_owned(),
            },
            inputs: vec![LineageNode::External {
                namespace: "bench-h".to_owned(),
                identifier: format!("observation-{ordinal:016x}"),
            }],
        },
    };
    let timestamp_base_u64 = ordinal
        .checked_mul(3)
        .and_then(|value| value.checked_add(1))
        .ok_or(BenchError::ArithmeticOverflow("journal timestamp"))?;
    let timestamp_base = i64::try_from(timestamp_base_u64)
        .map_err(|_| BenchError::ArithmeticOverflow("journal timestamp conversion"))?;
    let mut content_hasher = blake3::Hasher::new();
    content_hasher.update(b"contextdb-bench-m17-observation\0");
    content_hasher.update(&seed.to_be_bytes());
    content_hasher.update(&ordinal.to_be_bytes());
    Ok(ObservationUnit {
        id: observation_id,
        workspace_id,
        memory_spaces: NonEmptyVec::new(memory_space),
        source_id: source,
        stream_position: None,
        participants: NonEmptyVec::new(narrator),
        occurred_at: TimeRange::open_ended(TimestampMicros(timestamp_base)),
        observed_at: TimestampMicros(timestamp_base.saturating_add(1)),
        recorded_at: TimestampMicros(timestamp_base.saturating_add(2)),
        artifact_refs: Vec::new(),
        content_block_refs: vec![content_block],
        content_hash: ContentDigest::from_bytes(*content_hasher.finalize().as_bytes()),
        envelope,
    })
}

fn strong_id<T>(
    domain: u8,
    seed: u64,
    ordinal: u64,
    constructor: impl FnOnce(Uuid) -> contextdb_core::ValidationResult<T>,
) -> Result<T> {
    let high = u128::from(domain) << 120;
    let value = high | (u128::from(seed) << 56) | u128::from(ordinal.saturating_add(1));
    constructor(Uuid::from_u128(value)).map_err(|error| {
        BenchError::Integrity(format!(
            "deterministic strong ID construction failed: {error}"
        ))
    })
}

fn elapsed_ns(started: Instant) -> Result<u64> {
    u64::try_from(started.elapsed().as_nanos())
        .map_err(|_| BenchError::ArithmeticOverflow("native duration nanoseconds"))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "journal lifecycle tests use immediate failure semantics"
    )]

    use super::run_journal_operations;

    #[test]
    fn portable_backup_restores_and_reopens_exactly() {
        let directory = tempfile::tempdir().expect("tempdir");
        let outcome = run_journal_operations(
            5,
            17,
            &directory.path().join("source.redb"),
            &directory.path().join("restore.redb"),
        )
        .expect("journal scenario");
        assert!(outcome.restore_equal);
        assert!(outcome.reopen_equal);
        assert_eq!(outcome.synchronized_acknowledgements, 5);
        assert_eq!(outcome.commit_seq, 5);
    }
}
