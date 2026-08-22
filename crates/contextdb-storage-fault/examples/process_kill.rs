use std::env;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use contextdb_storage::{
    Durability, Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine, VerifyMode,
    WriteTransaction,
};
use contextdb_storage_redb::RedbStorage;
use serde::Serialize;

const CHILD_UNCOMMITTED: &str = "--child-uncommitted";
const CHILD_ACKNOWLEDGED: &str = "--child-acknowledged";

#[derive(Serialize)]
struct Case {
    name: &'static str,
    child_reached_barrier: bool,
    child_was_terminated: bool,
    reopened: bool,
    expected_value_visible: bool,
    head_sequence: u64,
    deep_verify_records: u64,
    passed: bool,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    backend: &'static str,
    durability: &'static str,
    cases: Vec<Case>,
    acknowledged_commits: u64,
    acknowledged_commits_recovered: u64,
    acknowledged_loss: u64,
    passed: bool,
    limitations: Vec<&'static str>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().collect::<Vec<_>>();
    if arguments
        .get(1)
        .is_some_and(|value| value == CHILD_UNCOMMITTED)
    {
        return child_uncommitted(arguments.get(2).ok_or("missing child database path")?);
    }
    if arguments
        .get(1)
        .is_some_and(|value| value == CHILD_ACKNOWLEDGED)
    {
        return child_acknowledged(arguments.get(2).ok_or("missing child database path")?);
    }
    parent()
}

fn child_uncommitted(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let database = RedbStorage::open(path)?;
    let mut transaction = database.begin_write()?;
    transaction.put(
        &Keyspace::new("process-kill")?,
        b"uncommitted".to_vec(),
        b"must-not-be-visible".to_vec(),
    )?;
    println!("STAGED");
    std::io::stdout().flush()?;
    thread::sleep(Duration::from_secs(300));
    transaction.rollback()?;
    Ok(())
}

fn child_acknowledged(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let database = RedbStorage::open(path)?;
    let mut transaction = database.begin_write()?;
    transaction.put(
        &Keyspace::new("process-kill")?,
        b"acknowledged".to_vec(),
        b"must-survive".to_vec(),
    )?;
    let receipt = transaction.commit(Durability::Sync)?;
    println!("ACK {} sync", receipt.sequence);
    std::io::stdout().flush()?;
    thread::sleep(Duration::from_secs(300));
    Ok(())
}

fn parent() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let uncommitted_path = directory.path().join("uncommitted.redb");
    let acknowledged_path = directory.path().join("acknowledged.redb");
    let uncommitted = run_case(CHILD_UNCOMMITTED, &uncommitted_path, false)?;
    let acknowledged = run_case(CHILD_ACKNOWLEDGED, &acknowledged_path, true)?;
    let acknowledged_loss = u64::from(!acknowledged.expected_value_visible);
    let report = Report {
        schema: "contextdb.process-kill-fault-matrix.v1",
        backend: "contextdb-storage-redb/redb-4.1.0",
        durability: "sync",
        acknowledged_commits: 1,
        acknowledged_commits_recovered: u64::from(acknowledged.expected_value_visible),
        acknowledged_loss,
        passed: uncommitted.passed && acknowledged.passed && acknowledged_loss == 0,
        cases: vec![uncommitted, acknowledged],
        limitations: vec![
            "This native process-kill proof covers the Windows host and redb backend.",
            "Journal stage failpoints, ENOSPC, lost-response replay, weak durability rejection, corruption, and portable restore are covered by contextdb-journal tests.",
            "Linux/macOS power-loss certification remains target-platform release evidence.",
        ],
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.passed {
        return Err("process-kill fault matrix failed".into());
    }
    Ok(())
}

fn run_case(
    mode: &str,
    path: &Path,
    expected_visible: bool,
) -> Result<Case, Box<dyn std::error::Error>> {
    let executable = env::current_exe()?;
    let mut child = Command::new(executable)
        .arg(mode)
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("child stdout was unavailable")?;
    let mut reader = BufReader::new(stdout);
    let mut barrier = String::new();
    let bytes = reader.read_line(&mut barrier)?;
    let child_reached_barrier = bytes > 0
        && match mode {
            CHILD_UNCOMMITTED => barrier.trim() == "STAGED",
            CHILD_ACKNOWLEDGED => barrier.trim() == "ACK 1 sync",
            _ => false,
        };
    let child_was_terminated = if child_reached_barrier {
        child.kill()?;
        child.wait()?.code().is_none_or(|code| code != 0)
    } else {
        let status = child.wait()?;
        !status.success()
    };

    let reopened_database = RedbStorage::open(path)?;
    let snapshot = reopened_database.begin_read(SnapshotSelector::Latest)?;
    let key = if expected_visible {
        b"acknowledged".as_slice()
    } else {
        b"uncommitted".as_slice()
    };
    let value = snapshot.get(&Keyspace::new("process-kill")?, key)?;
    let expected_value_visible = value.is_some();
    let head_sequence = snapshot.sequence();
    drop(snapshot);
    let verify = reopened_database.verify(VerifyMode::Deep)?;
    let passed = child_reached_barrier
        && child_was_terminated
        && expected_value_visible == expected_visible
        && head_sequence == u64::from(expected_visible)
        && verify.sequence == head_sequence;
    Ok(Case {
        name: if expected_visible {
            "kill_after_sync_ack"
        } else {
            "kill_with_uncommitted_transaction"
        },
        child_reached_barrier,
        child_was_terminated,
        reopened: true,
        expected_value_visible,
        head_sequence,
        deep_verify_records: verify.records,
        passed,
    })
}
