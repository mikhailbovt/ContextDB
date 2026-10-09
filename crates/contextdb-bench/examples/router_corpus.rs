//! Generate or cold verify the built-in synthetic router corpus. No model calls.

use contextdb_bench::router_corpus::{
    verify_builtin_router_corpus, verify_builtin_router_replay_corpus, write_builtin_router_corpus,
    write_builtin_router_replay_corpus,
};
use contextdb_recall::QueryBudget;
use std::{path::Path, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2
        || !matches!(
            args[0].as_str(),
            "build" | "verify" | "build-replay" | "verify-replay"
        )
    {
        return Err("usage: router_corpus build|verify|build-replay|verify-replay ABSOLUTE_OUTPUT_DIRECTORY".into());
    }
    let mut budget = QueryBudget::new(
        20_000_000,
        2 * 1024 * 1024 * 1024,
        Duration::from_secs(60),
        Default::default(),
    );
    let root = Path::new(&args[1]);
    let report = match args[0].as_str() {
        "build" => write_builtin_router_corpus(root, &mut budget)?,
        "verify" => verify_builtin_router_corpus(root, &mut budget)?,
        "build-replay" => write_builtin_router_replay_corpus(root, &mut budget)?,
        "verify-replay" => verify_builtin_router_replay_corpus(root, &mut budget)?,
        _ => unreachable!("command checked"),
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
