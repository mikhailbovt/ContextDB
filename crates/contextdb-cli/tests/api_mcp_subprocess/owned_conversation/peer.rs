use super::*;

pub(super) struct Peer {
    pub(super) python: PathBuf,
    pub(super) script: PathBuf,
    pub(super) log: PathBuf,
    pub(super) mode: &'static str,
}

impl Peer {
    pub(super) fn new(f: &Fixture, mode: &'static str) -> Self {
        let candidates = std::env::var_os("CONTEXTDB_TEST_PYTHON")
            .map(PathBuf::from)
            .map(|path| vec![path])
            .unwrap_or_else(|| {
                if cfg!(windows) {
                    vec![PathBuf::from("python"), PathBuf::from("python3")]
                } else {
                    vec![PathBuf::from("python3"), PathBuf::from("python")]
                }
            });
        let python = candidates
            .into_iter()
            .find_map(|candidate| {
                let output = Command::new(candidate)
                    .args(["-I", "-c", "import sys; print(sys.executable)"])
                    .output()
                    .ok()?;
                if !output.status.success() {
                    return None;
                }
                let executable = String::from_utf8(output.stdout).ok()?;
                Some(PathBuf::from(executable.trim()))
            })
            .expect("installed Python or CONTEXTDB_TEST_PYTHON for deterministic protocol fixture");
        Self {
            python: std::fs::canonicalize(python).expect("canonical fixture interpreter"),
            script: std::fs::canonicalize(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/api_mcp_subprocess/owned_conversation/peer.py"),
            )
            .expect("owned peer script"),
            log: std::fs::canonicalize(f.directory.path())
                .expect("canonical fixture root")
                .join("peer.jsonl"),
            mode,
        }
    }

    pub(super) fn config(&self) -> serde_json::Value {
        serde_json::json!({"program":self.python,"args":["-I","-u",self.script,"--log",self.log,"--mode",self.mode],
            "seed":17,"timeout_millis":if self.mode == "deadline" {10000} else {30000},
            "model_profile":{"id":"deterministic-owned-subprocess","family":"deterministic-fixture",
                "tokenizer_id":"contextdb.reference_unicode_tokens.v1","renderer":"compact",
                "max_context_tokens":8192,"reserved_output_tokens":512,"preferred_structured_format":"compact_text",
                "supports_tool_results":false,"supports_native_citations":false,"supports_prompt_caching":false,
                "position_profile":"critical_first","instruction_hierarchy":"separated_channels",
                "max_schema_complexity":64,"external_processing":false}})
    }

    pub(super) fn records(&self) -> Vec<serde_json::Value> {
        if !self.log.exists() {
            return vec![];
        }
        std::fs::read_to_string(&self.log)
            .expect("peer audit")
            .lines()
            .map(|line| serde_json::from_str(line).expect("peer audit JSONL"))
            .collect()
    }

    pub(super) fn sends(&self) -> Vec<serde_json::Value> {
        self.records()
            .into_iter()
            .filter(|record| record["request"]["op"] == "complete")
            .collect()
    }

    pub(super) fn assert_reaped(&self) {
        let processes: BTreeSet<_> = self
            .records()
            .iter()
            .map(|record| record["pid"].as_u64().expect("owned peer pid"))
            .collect();
        for process in processes {
            let pid = process.to_string();
            let output = Command::new(&self.python)
                .args(["-I", path(&self.script), "--alive-check", &pid])
                .output()
                .expect("read owned peer process state");
            assert!(output.status.success());
            let result: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("process state");
            assert_eq!(result["alive"], false, "reader child must be reaped");
        }
    }
}
