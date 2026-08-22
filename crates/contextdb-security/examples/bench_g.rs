fn main() -> Result<(), Box<dyn std::error::Error>> {
    let report = contextdb_security::run_reference_bench_g()?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.passed {
        return Err("BENCH-G release gate failed".into());
    }
    Ok(())
}
