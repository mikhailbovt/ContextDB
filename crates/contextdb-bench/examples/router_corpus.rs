//! Generate or cold verify the built-in synthetic router corpus. No model calls.

use contextdb_bench::router_corpus::{verify_builtin_router_corpus, write_builtin_router_corpus};
use contextdb_recall::QueryBudget;
use std::{path::Path, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 || !matches!(args[0].as_str(), "build" | "verify") {
        return Err("usage: router_corpus build|verify ABSOLUTE_OUTPUT_DIRECTORY".into());
    }
    let mut budget = QueryBudget::new(
        20_000_000,
        2 * 1024 * 1024 * 1024,
        Duration::from_secs(60),
        Default::default(),
    );
    let report = if args[0] == "build" {
        write_builtin_router_corpus(Path::new(&args[1]), &mut budget)?
    } else {
        verify_builtin_router_corpus(Path::new(&args[1]), &mut budget)?
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
