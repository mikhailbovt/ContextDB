//! Minimal executable used by the M0 workspace gate.

fn main() {
    let database = contextdb_reference::ContextDb::new("embedded-example")
        .expect("the static example database identifier is valid");
    let snapshot = database
        .snapshot()
        .expect("a newly created reference database has a snapshot");
    println!(
        "ContextDB embedded reference example {} at commit {}",
        env!("CARGO_PKG_VERSION"),
        snapshot.commit_seq
    );
}
