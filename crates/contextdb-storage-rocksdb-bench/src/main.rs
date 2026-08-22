//! Explicit RocksDB leg of the deterministic ContextDB M2 workload.

use std::hint::black_box;
use std::time::{Duration, Instant};

use contextdb_storage::{
    Durability, Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine, WriteTransaction,
};
use contextdb_storage_rocksdb_bench::RocksDbStorage;
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

fn measure(engine: &RocksDbStorage, records: u64) -> Result<Measurement, String> {
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
    let batch_write_ns = nanos(started.elapsed());

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
            .ok_or_else(|| format!("rocksdb: missing record {selected}"))?;
        checksum = checksum.wrapping_add(u64::from(found[0]));
        black_box(found);
    }
    let point_reads_ns = nanos(started.elapsed());

    let started = Instant::now();
    for subject in 0..64_u64 {
        let prefix = format!("subject/{subject:04}/");
        let entries = snapshot
            .scan_prefix(&semantic, prefix.as_bytes())
            .map_err(|error| error.to_string())?;
        checksum = checksum.wrapping_add(u64::try_from(entries.len()).unwrap_or(u64::MAX));
        black_box(entries);
    }
    let subject_prefix_scans_ns = nanos(started.elapsed());

    let started = Instant::now();
    for source in 0..256_u64 {
        let prefix = format!("out/{source:06}/");
        let entries = snapshot
            .scan_prefix(&graph, prefix.as_bytes())
            .map_err(|error| error.to_string())?;
        checksum = checksum.wrapping_add(u64::try_from(entries.len()).unwrap_or(u64::MAX));
        black_box(entries);
    }
    let graph_prefix_scans_ns = nanos(started.elapsed());

    let started = Instant::now();
    let report = engine
        .verify(contextdb_storage::VerifyMode::Deep)
        .map_err(|error| error.to_string())?;
    checksum = checksum.wrapping_add(report.records);
    let verify_ns = nanos(started.elapsed());

    Ok(Measurement {
        backend: "rocksdb-0.24.0/librocksdb-10.4.2",
        records,
        value_bytes: VALUE_BYTES,
        batch_records: BATCH_RECORDS,
        commits,
        seed: SEED,
        batch_write_ns,
        point_reads_ns,
        subject_prefix_scans_ns,
        graph_prefix_scans_ns,
        verify_ns,
        checksum,
    })
}

fn nanos(duration: Duration) -> u128 {
    duration.as_nanos()
}

fn run() -> Result<Measurement, String> {
    let records = std::env::args()
        .nth(1)
        .map_or(Ok(DEFAULT_RECORDS), |value| {
            value
                .parse::<u64>()
                .map_err(|error| format!("invalid record count: {error}"))
        })?;
    if records == 0 {
        return Err("record count must be positive".to_owned());
    }
    let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
    let engine = RocksDbStorage::open(directory.path()).map_err(|error| error.to_string())?;
    measure(&engine, records)
}

fn main() {
    match run()
        .and_then(|result| serde_json::to_string_pretty(&result).map_err(|error| error.to_string()))
    {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("RocksDB bake-off failed: {error}");
            std::process::exit(1);
        }
    }
}
