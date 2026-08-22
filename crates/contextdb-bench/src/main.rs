//! Bounded native M17 benchmark executable.

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use contextdb_bench::{
    BenchConfig, BuildProfile, NativeRunMetadata, ReleaseChannel, SemanticAdmission,
    SemanticWorkloadConfig, SemanticWorkloadPreset, TelemetryBudget, admit_semantic_workload,
    build_native_report, detect_semantic_host_capacity, run_native_redb_at,
    run_semantic_crash_child, run_semantic_workload, sha256_hex, write_semantic_admission,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("contextdb-bench failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if let Some(root) = crash_child(&arguments)? {
        run_semantic_crash_child(&root)?;
        return Ok(());
    }
    if arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), "--semantic-admission" | "--semantic-run"))
    {
        return run_semantic(&arguments);
    }
    let options = Options::parse(&arguments)?;
    if options.output.exists() {
        return Err("output directory must be fresh so evidence is never overwritten".into());
    }
    std::fs::create_dir_all(&options.output)?;
    let started_at = utc_now()?;
    let outcome = run_native_redb_at(
        options.config,
        TelemetryBudget::default(),
        &options.output.join("native-state"),
    )?;
    let finished_at = utc_now()?;
    let raw_bytes = serde_json::to_vec_pretty(&outcome)?;
    let raw_name = "raw-native-outcome.json";
    std::fs::write(options.output.join(raw_name), &raw_bytes)?;
    let report = build_native_report(
        &outcome,
        detect_metadata(started_at, finished_at),
        raw_name,
        &raw_bytes,
    )?;
    let report_bytes = serde_json::to_vec_pretty(&report)?;
    std::fs::write(options.output.join("benchmark-result.json"), &report_bytes)?;
    println!("{}", String::from_utf8(report_bytes)?);
    Ok(())
}

#[derive(Debug)]
struct Options {
    output: PathBuf,
    config: BenchConfig,
}

impl Options {
    fn parse(arguments: &[String]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut arguments = arguments.iter();
        let mut output = None;
        let mut smoke = false;
        let mut records = None;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--output" => {
                    output = Some(PathBuf::from(
                        arguments.next().ok_or("--output requires a path")?,
                    ));
                }
                "--smoke" => smoke = true,
                "--records" => {
                    records = Some(
                        arguments
                            .next()
                            .ok_or("--records requires a positive integer")?
                            .parse::<u64>()?,
                    );
                }
                "--help" | "-h" => {
                    println!(
                        "Usage: contextdb-bench --output <fresh-directory> [--smoke | --records N]\n\
                         Default: bounded 20,000-record development run.\n\
                         All CLI runs are native_measured_development and cannot claim release proof."
                    );
                    std::process::exit(0);
                }
                _ => return Err(format!("unknown argument: {argument}").into()),
            }
        }
        if smoke && records.is_some() {
            return Err("--smoke and --records are mutually exclusive".into());
        }
        let output = output.ok_or("--output is required")?;
        let config = if smoke {
            BenchConfig::smoke()
        } else if let Some(records) = records {
            BenchConfig::development().with_records(records)?
        } else {
            BenchConfig::development()
        };
        Ok(Self { output, config })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SemanticAction {
    Admission,
    Run,
}

#[derive(Debug)]
struct SemanticOptions {
    action: SemanticAction,
    output: PathBuf,
    config: Option<SemanticWorkloadConfig>,
    confirmation: Option<String>,
}

impl SemanticOptions {
    fn parse(arguments: &[String]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut action = None;
        let mut output = None;
        let mut preset = SemanticWorkloadPreset::Smoke;
        let mut semantic_nodes = None;
        let mut graph_edges = None;
        let mut vectors = None;
        let mut vector_dimensions = None;
        let mut node_batch_size = None;
        let mut edge_batch_size = None;
        let mut queries = None;
        let mut rss_budget = None;
        let mut confirmation = None;
        let mut require_crash_probe = true;
        let mut cursor = arguments.iter();
        while let Some(argument) = cursor.next() {
            match argument.as_str() {
                "--semantic-admission" => set_action(&mut action, SemanticAction::Admission)?,
                "--semantic-run" => set_action(&mut action, SemanticAction::Run)?,
                "--output" => {
                    output = Some(PathBuf::from(
                        cursor.next().ok_or("--output requires a path")?,
                    ));
                }
                "--preset" => {
                    preset =
                        parse_semantic_preset(cursor.next().ok_or("--preset requires a value")?)?;
                }
                "--semantic-nodes" => semantic_nodes = Some(parse_u64(&mut cursor, argument)?),
                "--graph-edges" => graph_edges = Some(parse_u64(&mut cursor, argument)?),
                "--vectors" => vectors = Some(parse_u64(&mut cursor, argument)?),
                "--vector-dimensions" => {
                    vector_dimensions = Some(parse_u64(&mut cursor, argument)?.try_into()?)
                }
                "--node-batch-size" => node_batch_size = Some(parse_u64(&mut cursor, argument)?),
                "--edge-batch-size" => edge_batch_size = Some(parse_u64(&mut cursor, argument)?),
                "--queries" => queries = Some(parse_u64(&mut cursor, argument)?),
                "--rss-budget-bytes" => rss_budget = Some(parse_u64(&mut cursor, argument)?),
                "--confirm-admission" => {
                    confirmation = Some(
                        cursor
                            .next()
                            .ok_or("--confirm-admission requires a SHA-256")?
                            .clone(),
                    );
                }
                "--no-crash-probe" => require_crash_probe = false,
                "--help" | "-h" => {
                    semantic_help();
                    std::process::exit(0);
                }
                _ => return Err(format!("unknown semantic argument: {argument}").into()),
            }
        }
        let action = action.ok_or("one semantic action is required")?;
        let output = output.ok_or("--output is required")?;
        if action == SemanticAction::Run {
            if semantic_nodes.is_some()
                || graph_edges.is_some()
                || vectors.is_some()
                || vector_dimensions.is_some()
                || node_batch_size.is_some()
                || edge_batch_size.is_some()
                || queries.is_some()
                || rss_budget.is_some()
                || preset != SemanticWorkloadPreset::Smoke
                || !require_crash_probe
            {
                return Err(
                    "semantic execution reads its exact configuration from the confirmed admission artifact; scale flags are not accepted"
                        .into(),
                );
            }
            if confirmation.is_none() {
                return Err("--semantic-run requires --confirm-admission SHA256".into());
            }
            return Ok(Self {
                action,
                output,
                config: None,
                confirmation,
            });
        }
        if confirmation.is_some() {
            return Err("--confirm-admission is valid only with --semantic-run".into());
        }
        let mut config = SemanticWorkloadConfig::preset(preset);
        if let Some(value) = semantic_nodes {
            config.semantic_nodes = value;
            config.preset = SemanticWorkloadPreset::Custom;
        }
        if let Some(value) = graph_edges {
            config.graph_edges = value;
            config.preset = SemanticWorkloadPreset::Custom;
        }
        if let Some(value) = vectors {
            config.vectors = value;
            config.preset = SemanticWorkloadPreset::Custom;
        }
        if let Some(value) = vector_dimensions {
            config.vector_dimensions = value;
            config.preset = SemanticWorkloadPreset::Custom;
        }
        if let Some(value) = node_batch_size {
            config.node_batch_size = value;
        }
        if let Some(value) = edge_batch_size {
            config.edge_batch_size = value;
        }
        if let Some(value) = queries {
            config.queries_per_scenario = value;
        }
        if let Some(value) = rss_budget {
            config.process_rss_budget_bytes = value;
        }
        config.require_crash_probe = require_crash_probe;
        config.validate()?;
        Ok(Self {
            action,
            output,
            config: Some(config),
            confirmation: None,
        })
    }
}

fn run_semantic(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let options = SemanticOptions::parse(arguments)?;
    match options.action {
        SemanticAction::Admission => {
            if options.output.join("semantic-admission.json").exists() {
                return Err("semantic admission output already exists".into());
            }
            let config = options
                .config
                .ok_or("semantic admission config is absent")?;
            let host = detect_semantic_host_capacity(&options.output);
            let admission = admit_semantic_workload(config, host)?;
            let digest = write_semantic_admission(&options.output, &admission)?;
            println!("{}", serde_json::to_string_pretty(&admission)?);
            eprintln!("contextdb-bench semantic_admission_sha256={digest}");
        }
        SemanticAction::Run => {
            let path = options.output.join("semantic-admission.json");
            let bytes = std::fs::read(&path)?;
            let digest = sha256_hex(&bytes);
            if Some(digest.as_str()) != options.confirmation.as_deref() {
                return Err("--confirm-admission does not match semantic-admission.json".into());
            }
            let admission: SemanticAdmission = serde_json::from_slice(&bytes)?;
            let executable = std::env::current_exe()?;
            let index =
                run_semantic_workload(&options.output, &admission, &digest, Some(&executable))?;
            println!("{}", serde_json::to_string_pretty(&index)?);
        }
    }
    Ok(())
}

fn crash_child(arguments: &[String]) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    if arguments.first().map(String::as_str) != Some("--semantic-crash-child") {
        return Ok(None);
    }
    if arguments.len() != 2 {
        return Err("--semantic-crash-child requires exactly one state path".into());
    }
    Ok(Some(PathBuf::from(&arguments[1])))
}

fn set_action(
    action: &mut Option<SemanticAction>,
    value: SemanticAction,
) -> Result<(), Box<dyn std::error::Error>> {
    if action.replace(value).is_some() {
        return Err("semantic actions are mutually exclusive".into());
    }
    Ok(())
}

fn parse_u64<'a>(
    cursor: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(cursor
        .next()
        .ok_or_else(|| format!("{flag} requires a positive integer"))?
        .parse()?)
}

fn parse_semantic_preset(value: &str) -> Result<SemanticWorkloadPreset, String> {
    match value {
        "smoke" => Ok(SemanticWorkloadPreset::Smoke),
        "development" => Ok(SemanticWorkloadPreset::Development),
        "small" => Ok(SemanticWorkloadPreset::Small),
        "medium" => Ok(SemanticWorkloadPreset::Medium),
        "certification-v1" => Ok(SemanticWorkloadPreset::CertificationV1),
        _ => Err(format!("unknown semantic preset: {value}")),
    }
}

fn semantic_help() {
    println!(
        "Semantic BENCH-H:\n\
         contextdb-bench --semantic-admission --output <fresh-or-empty-directory> [--preset smoke|development|small|medium|certification-v1] [scale/resource overrides]\n\
         contextdb-bench --semantic-run --output <admission-directory> --confirm-admission <sha256>\n\
         Admission is machine-readable; certification remains blocked until persistent policy-universe/server composition, 1M-vector reference-hardware proof, and host capacity requirements pass."
    );
}

fn detect_metadata(started_at: String, finished_at: String) -> NativeRunMetadata {
    let git_commit = command_output("git", &["rev-parse", "HEAD"])
        .filter(|value| value.len() == 40)
        .unwrap_or_else(|| "0".repeat(40));
    let dirty =
        command_output("git", &["status", "--porcelain"]).is_none_or(|value| !value.is_empty());
    let rustc =
        command_output("rustc", &["--version"]).unwrap_or_else(|| "rustc unavailable".to_owned());
    let cargo =
        command_output("cargo", &["--version"]).unwrap_or_else(|| "cargo unavailable".to_owned());
    let verbose_rustc = command_output("rustc", &["--version", "--verbose"]);
    let target = verbose_rustc
        .as_deref()
        .and_then(|value| value.lines().find_map(|line| line.strip_prefix("host: ")))
        .unwrap_or(std::env::consts::ARCH)
        .to_owned();
    let os_version = if cfg!(target_os = "windows") {
        command_output(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[System.Environment]::OSVersion.VersionString",
            ],
        )
        .unwrap_or_else(|| "not-measured".to_owned())
    } else {
        command_output("uname", &["-sr"]).unwrap_or_else(|| "not-measured".to_owned())
    };
    let memory_bytes = if cfg!(target_os = "windows") {
        command_output(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            ],
        )
        .and_then(|value| value.parse().ok())
        .unwrap_or(1)
    } else {
        1
    };
    NativeRunMetadata {
        started_at,
        finished_at,
        git_commit,
        dirty,
        release_channel: ReleaseChannel::Development,
        build_profile: if cfg!(debug_assertions) {
            BuildProfile::Dev
        } else {
            BuildProfile::Release
        },
        os: std::env::consts::OS.to_owned(),
        os_version,
        kernel: None,
        architecture: std::env::consts::ARCH.to_owned(),
        cpu: std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| "not-measured".to_owned()),
        logical_cores: std::thread::available_parallelism()
            .map_or(1, |cores| u32::try_from(cores.get()).unwrap_or(u32::MAX)),
        memory_bytes,
        storage: "local temporary redb file".to_owned(),
        filesystem: "not-measured".to_owned(),
        rustc,
        cargo,
        target,
    }
}

fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
}

fn utc_now() -> Result<String, std::time::SystemTimeError> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(format_unix_seconds(seconds))
}

fn format_unix_seconds(seconds: u64) -> String {
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let seconds_in_day = seconds % 86_400;
    let hour = seconds_in_day / 3_600;
    let minute = (seconds_in_day % 3_600) / 60;
    let second = seconds_in_day % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

// Howard Hinnant's civil_from_days transformation for the Unix epoch.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let shifted = days_since_epoch.saturating_add(719_468);
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (
        year,
        u32::try_from(month).unwrap_or(u32::MAX),
        u32::try_from(day).unwrap_or(u32::MAX),
    )
}

#[cfg(test)]
mod tests {
    use super::format_unix_seconds;

    #[test]
    fn unix_timestamp_is_rfc3339_utc() {
        assert_eq!(format_unix_seconds(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_seconds(1_786_492_800), "2026-08-12T00:00:00Z");
    }
}
