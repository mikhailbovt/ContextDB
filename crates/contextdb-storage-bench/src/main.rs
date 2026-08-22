//! Reproducible, deterministic substrate micro-benchmark for M2.

use std::hint::black_box;
use std::time::{Duration, Instant};

use contextdb_storage::{
    Durability, Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine, WriteTransaction,
};
use contextdb_storage_fjall::FjallStorage;
use contextdb_storage_memory::MemoryStorage;
use contextdb_storage_redb::RedbStorage;
use serde::Serialize;

const DEFAULT_RECORDS: u64 = 20_000;
const VALUE_BYTES: usize = 256;
const BATCH_RECORDS: u64 = 250;
const SEED: u64 = 0xC07E_57DB_0000_0002;

#[derive(Debug, Serialize)]
struct Measurement {
    backend: &'static str,
    records: u64,
    value_bytes: usize,
    batch_records: u64,
    commits: u64,
    seed: u64,
    batch_write_ns: u128,
    point_reads_ns: u128,
    subject_prefix_scans_ns: u128,
    graph_prefix_scans_ns: u128,
    verify_ns: u128,
    checksum: u64,
}

fn key(index: u64) -> Vec<u8> {
    format!("subject/{:04}/claim/{index:016x}", index % 64).into_bytes()
}

fn value(index: u64) -> Vec<u8> {
    let mut value = vec![0_u8; VALUE_BYTES];
    for (offset, byte) in value.iter_mut().enumerate() {
        *byte = index
            .wrapping_add(u64::try_from(offset).unwrap_or(u64::MAX))
            .to_le_bytes()[0];
    }
    value
}

fn edge_key(index: u64) -> Vec<u8> {
    format!("out/{:06}/edge/{index:016x}", index % 256).into_bytes()
}

fn permutation(index: u64, records: u64) -> u64 {
    index
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(SEED)
        % records
}

fn measure<E: StorageEngine>(
    backend: &'static str,
    engine: &E,
    records: u64,
) -> Result<Measurement, String> {
    let semantic = Keyspace::new("semantic").map_err(|error| error.to_string())?;
    let graph = Keyspace::new("graph").map_err(|error| error.to_string())?;

    let started = Instant::now();
    let mut first = 0_u64;
    let mut commits = 0_u64;
    while first < records {
        let end = first.saturating_add(BATCH_RECORDS).min(records);
        let mut transaction = engine.begin_write().map_err(|error| error.to_string())?;
        for index in first..end {
            transaction
                .put(&semantic, key(index), value(index))
                .map_err(|error| error.to_string())?;
            transaction
                .put(&graph, edge_key(index), value(index ^ SEED))
                .map_err(|error| error.to_string())?;
        }
        transaction
            .commit(Durability::Sync)
            .map_err(|error| error.to_string())?;
        commits = commits.saturating_add(1);
        first = end;
    }
    let batch_write = started.elapsed();

    let snapshot = engine
        .begin_read(SnapshotSelector::Latest)
        .map_err(|error| error.to_string())?;
    let started = Instant::now();
    let mut checksum = 0_u64;
    for index in 0..records {
        let selected = permutation(index, records);
        let found = snapshot
            .get(&semantic, &key(selected))
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("{backend}: missing record {selected}"))?;
        checksum = checksum.wrapping_add(u64::from(found[0]));
        black_box(&found);
    }
    let point_reads = started.elapsed();

    let started = Instant::now();
    for subject in 0..64_u64 {
        let prefix = format!("subject/{subject:04}/");
        let entries = snapshot
            .scan_prefix(&semantic, prefix.as_bytes())
            .map_err(|error| error.to_string())?;
        checksum = checksum.wrapping_add(u64::try_from(entries.len()).unwrap_or(u64::MAX));
        black_box(entries);
    }
    let subject_prefix_scans = started.elapsed();

    let started = Instant::now();
    for source in 0..256_u64 {
        let prefix = format!("out/{source:06}/");
        let entries = snapshot
            .scan_prefix(&graph, prefix.as_bytes())
            .map_err(|error| error.to_string())?;
        checksum = checksum.wrapping_add(u64::try_from(entries.len()).unwrap_or(u64::MAX));
        black_box(entries);
    }
    let graph_prefix_scans = started.elapsed();

    let started = Instant::now();
    let report = engine
        .verify(contextdb_storage::VerifyMode::Deep)
        .map_err(|error| error.to_string())?;
    checksum = checksum.wrapping_add(report.records);
    let verify = started.elapsed();

    Ok(Measurement {
        backend,
        records,
        value_bytes: VALUE_BYTES,
        batch_records: BATCH_RECORDS,
        commits,
        seed: SEED,
        batch_write_ns: nanos(batch_write),
        point_reads_ns: nanos(point_reads),
        subject_prefix_scans_ns: nanos(subject_prefix_scans),
        graph_prefix_scans_ns: nanos(graph_prefix_scans),
        verify_ns: nanos(verify),
        checksum,
    })
}

fn nanos(duration: Duration) -> u128 {
    duration.as_nanos()
}

fn parse_records() -> Result<u64, String> {
    let Some(value) = std::env::args().nth(1) else {
        return Ok(DEFAULT_RECORDS);
    };
    let parsed = value
        .parse::<u64>()
        .map_err(|error| format!("invalid record count: {error}"))?;
    if parsed == 0 {
        return Err("record count must be positive".to_owned());
    }
    Ok(parsed)
}

fn run() -> Result<Vec<Measurement>, String> {
    let records = parse_records()?;
    let memory = MemoryStorage::new();
    let fjall_directory = tempfile::tempdir().map_err(|error| error.to_string())?;
    let redb_directory = tempfile::tempdir().map_err(|error| error.to_string())?;
    let fjall = FjallStorage::open(fjall_directory.path()).map_err(|error| error.to_string())?;
    let redb = RedbStorage::open(redb_directory.path().join("bakeoff.redb"))
        .map_err(|error| error.to_string())?;
    Ok(vec![
        measure("memory", &memory, records)?,
        measure("fjall-3.1.8", &fjall, records)?,
        measure("redb-4.1.0", &redb, records)?,
    ])
}

fn main() {
    match run().and_then(|measurements| {
        serde_json::to_string_pretty(&measurements).map_err(|error| error.to_string())
    }) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("storage bake-off failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use contextdb_storage::{
        CompactRequest, Durability, Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine,
        StorageError, VerifyMode, WriteTransaction,
    };
    use contextdb_storage_fjall::FjallStorage;
    use contextdb_storage_memory::MemoryStorage;
    use contextdb_storage_redb::RedbStorage;

    use super::{key, permutation};

    fn storage_conformance<E: StorageEngine>(engine: &E) {
        let semantic = Keyspace::new("semantic").expect("portable keyspace");
        let graph = Keyspace::new("graph").expect("portable keyspace");
        assert_eq!(engine.head_sequence().expect("head"), 0);

        let mut first = engine.begin_write().expect("first writer");
        first
            .put(&semantic, b"subject/2".to_vec(), b"two-v1".to_vec())
            .expect("put semantic two");
        first
            .put(&semantic, b"subject/1".to_vec(), b"one-v1".to_vec())
            .expect("put semantic one");
        first
            .put(&graph, b"out/1/2".to_vec(), b"edge-v1".to_vec())
            .expect("put graph edge");
        let first_receipt = first.commit(Durability::Sync).expect("commit first");
        assert_eq!(first_receipt.sequence, 1);
        assert_eq!(first_receipt.durability, Durability::Sync);

        let old = engine
            .begin_read(SnapshotSelector::At(1))
            .expect("snapshot one");
        let old_entries = old
            .scan_prefix(&semantic, b"subject/")
            .expect("ordered prefix scan");
        assert_eq!(
            old_entries
                .iter()
                .map(|entry| entry.key.as_slice())
                .collect::<Vec<_>>(),
            vec![b"subject/1".as_slice(), b"subject/2".as_slice()]
        );

        let mut second = engine.begin_write().expect("second writer");
        second
            .put(&semantic, b"subject/1".to_vec(), b"one-v2".to_vec())
            .expect("replace semantic one");
        second
            .delete(&semantic, b"subject/2".to_vec())
            .expect("delete semantic two");
        second
            .put(&graph, b"out/2/1".to_vec(), b"edge-v2".to_vec())
            .expect("put second graph edge");
        assert_eq!(
            second
                .commit(Durability::Sync)
                .expect("commit second")
                .sequence,
            2
        );

        assert_eq!(
            old.get(&semantic, b"subject/1").expect("old read"),
            Some(b"one-v1".to_vec()),
            "a retained read snapshot must not drift after publication"
        );
        assert_eq!(
            old.get(&semantic, b"subject/2").expect("old read"),
            Some(b"two-v1".to_vec())
        );

        let latest = engine
            .begin_read(SnapshotSelector::Latest)
            .expect("latest snapshot");
        assert_eq!(latest.sequence(), 2);
        assert_eq!(
            latest.get(&semantic, b"subject/1").expect("latest read"),
            Some(b"one-v2".to_vec())
        );
        assert_eq!(
            latest.get(&semantic, b"subject/2").expect("latest read"),
            None
        );
        drop(latest);
        drop(old);

        let mut abandoned = engine.begin_write().expect("rollback writer");
        abandoned
            .put(&semantic, b"subject/3".to_vec(), b"never".to_vec())
            .expect("stage rollback value");
        abandoned.rollback().expect("rollback");
        assert_eq!(engine.head_sequence().expect("head after rollback"), 2);
        assert_eq!(
            engine
                .begin_read(SnapshotSelector::Latest)
                .expect("latest after rollback")
                .get(&semantic, b"subject/3")
                .expect("read rolled-back value"),
            None
        );

        let verified = engine.verify(VerifyMode::Deep).expect("deep verify");
        assert_eq!(verified.sequence, 2);
        assert_eq!(verified.records, 3);
        let compacted = engine
            .compact(CompactRequest::default())
            .expect("physical compaction");
        assert_eq!(compacted.sequence, 2);
        assert_eq!(engine.head_sequence().expect("head after compaction"), 2);

        let directory = tempfile::tempdir().expect("checkpoint target parent");
        assert!(matches!(
            engine.checkpoint(&directory.path().join("physical-checkpoint")),
            Err(StorageError::Unsupported { .. })
        ));
    }

    #[test]
    fn workload_is_deterministic() {
        assert_eq!(key(42), key(42));
        assert_eq!(permutation(100, 1_000), permutation(100, 1_000));
    }

    #[test]
    fn memory_satisfies_shared_storage_contract() {
        storage_conformance(&MemoryStorage::new());
    }

    #[test]
    fn fjall_satisfies_shared_storage_contract() {
        let directory = tempfile::tempdir().expect("temporary Fjall directory");
        let storage = FjallStorage::open(directory.path()).expect("open Fjall");
        storage_conformance(&storage);
    }

    #[test]
    fn redb_satisfies_shared_storage_contract() {
        let directory = tempfile::tempdir().expect("temporary redb directory");
        let storage =
            RedbStorage::open(directory.path().join("conformance.redb")).expect("open redb");
        storage_conformance(&storage);
    }
}
