//! Emit the common synthetic history, with evaluation targets in a separate field.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let distractors = std::env::args()
        .nth(1)
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or(1_000);
    if distractors > 1_000_000 {
        return Err("at most one million distractors are supported".into());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&contextdb_bench::continuous_history(distractors))?
    );
    Ok(())
}
