//! Admission, association and real owned-child cleanup, without a model.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
};

use contextdb_recall::QueryCancellation;
use serde_json::{Value, json};

use super::*;

fn python() -> PathBuf {
    let choices = std::env::var_os("CONTEXTDB_TEST_PYTHON")
        .map(PathBuf::from)
        .map(|path| vec![path])
        .unwrap_or_else(|| {
            if cfg!(windows) {
                vec![PathBuf::from("python"), PathBuf::from("python3")]
            } else {
                vec![PathBuf::from("python3"), PathBuf::from("python")]
            }
        });
    choices
        .into_iter()
        .find_map(|path| {
            let output = Command::new(path)
                .args(["-I", "-c", "import sys; print(sys.executable)"])
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            fs::canonicalize(String::from_utf8(output.stdout).ok()?.trim()).ok()
        })
        .expect("installed Python or CONTEXTDB_TEST_PYTHON for deterministic IPC fixture")
}

const PEER: &str = r#"import sys,json,struct,time
args=dict(zip(sys.argv[1::2],sys.argv[2::2]))
def send(value):
    meta=json.dumps(value,separators=(',',':')).encode()
    sys.stdout.buffer.write(struct.pack('>IH',len(meta)+2,len(meta))+meta)
    sys.stdout.buffer.flush()
send({'fixture':'memory-free'})
while True:
    prefix=sys.stdin.buffer.read(4)
    if not prefix: break
    size=struct.unpack('>I',prefix)[0]
    body=sys.stdin.buffer.read(size)
    n=struct.unpack('>H',body[:2])[0]
    meta=json.loads(body[2:2+n])
    if meta['timeout_micros']==1: time.sleep(2)
    send({'format':meta['format'],'operation':'score','id':meta['id'],
          'config_sha256':meta['config_sha256'],'input_sha256':meta['input_sha256'],
          'status':'ok','yes_minus_no':1.0})
"#;

pub(in crate::owned_conversation) fn fixture_config(root: &Path, program: PathBuf) -> KevConfig {
    fs::create_dir(root.join("corpus")).expect("fixture public corpus");
    fs::create_dir(root.join("runs")).expect("fixture runs");
    fs::create_dir(root.join("runs/dev")).expect("fixture bundle");
    for name in [
        "corpus.py",
        "trainer.py",
        "check.py",
        "conditional.py",
        "model-lock.json",
    ] {
        fs::write(root.join(name), b"").expect("fixture pinned file");
    }
    fs::write(root.join("worker.py"), PEER).expect("fixture worker");
    fs::write(root.join("runs/dev/bundle.json"), b"{}").expect("fixture bundle manifest");
    fs::write(root.join("runs/dev/complete.json"), b"{}").expect("fixture completion");
    serde_json::from_value(json!({
        "program":program,"args":["-I","-u"],
        "executable_sha256":sha256(&fs::read(&program).expect("fixture executable")),
        "worker":root.join("worker.py"),"worker_sha256":sha256(PEER.as_bytes()),
        "corpus":root.join("corpus"),"model_lock":root.join("model-lock.json"),
        "model_lock_sha256":sha256(b""),"output_root":root.join("runs"),"run_name":"dev",
        "bundle_sha256":sha256(b"{}"),"model_profile_sha256":"aa".repeat(32),
        "tensor_sha256":"bb".repeat(32),
        "source_sha256":{"corpus.py":sha256(b""),"trainer.py":sha256(b""),
            "check.py":sha256(b""),"conditional.py":sha256(b"")},
        "development_only":true,"model_processing":true,"failure_policy":"refuse",
        "limits":{"startup_timeout_micros":5_000_000,"per_call_timeout_micros":100_000,
            "aggregate_timeout_micros":1_000_000,"inference_work":128}
    }))
    .expect("strict bounded fixture config")
}

fn parse_reply(value: Value) -> Result<Option<u64>> {
    let reply: ScoreReply =
        serde_json::from_value(value).map_err(|_| refused("test reply refused"))?;
    validate_reply(reply, 1, "aa", "bb")
}

#[test]
fn strict_frames_associations_and_sigmoid_stop_refuse_malformed_inputs() {
    let value = json!({"format":FORMAT,"operation":"score","id":1,
        "config_sha256":"aa","input_sha256":"bb","status":"ok","yes_minus_no":1.0});
    assert!(
        parse_reply(value.clone())
            .expect("independent finite utility")
            .is_some()
    );
    for (key, replacement) in [
        ("id", json!(0)),
        ("config_sha256", json!("other")),
        ("input_sha256", json!("other")),
        ("operation", json!("ready")),
        ("code", json!("inference_refused")),
        ("yes_minus_no", json!(null)),
    ] {
        let mut changed = value.clone();
        changed[key] = replacement;
        assert!(
            parse_reply(changed).is_err(),
            "strict association/shape {key}"
        );
    }
    assert!(serde_json::from_slice::<ScoreReply>(br#"{"status":"ok","format":"x","format":"x","operation":"score","id":1,"config_sha256":"a","input_sha256":"b","yes_minus_no":1}"#).is_err());
    for (code, expected) in [
        (
            "projection_refused",
            ContextError::InvalidRequest("worker semantic projection unsupported".into()),
        ),
        (
            "token_refused",
            ContextError::Tokenizer("worker token admission refused".into()),
        ),
        (
            "deadline_refused",
            ContextError::BudgetExceeded("worker inference deadline refused".into()),
        ),
        (
            "resource_refused",
            ContextError::BudgetExceeded("worker inference resource refused".into()),
        ),
        ("inference_refused", refused("worker inference refused")),
        ("nonfinite_score", refused("worker score nonfinite")),
    ] {
        let mut error = json!({"format":FORMAT,"operation":"score","id":1,
            "config_sha256":"aa","input_sha256":"bb","status":"error","code":code});
        assert_eq!(
            parse_reply(error.clone()).expect_err("typed safe refusal"),
            expected
        );
        error["id"] = json!(0);
        assert_eq!(
            parse_reply(error).expect_err("correlation precedes code"),
            refused("worker reply association differs")
        );
    }
    assert_eq!(utility(0.0).expect("zero STOP"), None);
    assert_eq!(utility(-1e6).expect("stable negative STOP"), None);
    assert_eq!(utility(1e6).expect("stable positive"), Some(1_000_000));
    assert!(utility(f64::NAN).is_err());
    assert!(utility(f64::INFINITY).is_err());
    assert!(utility(1_000_001.0).is_err());
    let frame = transport::frame(b"{}", Vec::new()).expect("bounded reply frame");
    assert_eq!(transport::decode_reply(&frame).expect("exact reply"), b"{}");
    let mut truncated = frame.to_vec();
    truncated.pop();
    assert!(transport::decode_reply(&truncated).is_err());
    assert!(transport::decode_reply(&u32::MAX.to_be_bytes()).is_err());
    assert!(transport::decode_reply(&[0, 0, 0, 3, 0, 0, 1]).is_err());
    assert!(transport::frame(&vec![b'x'; MAX_META + 1], vec![]).is_err());
}

#[test]
fn pinned_development_policy_changes_the_binding_and_rejects_code_or_capability_drift() {
    let directory = tempfile::tempdir().expect("owned files");
    let root = fs::canonicalize(directory.path()).expect("canonical owned root");
    let program = root.join("interpreter");
    fs::write(&program, b"pinned test interpreter; never executed")
        .expect("owned admission fixture");
    let config = fixture_config(&root, program);
    config.validate().expect("all exact code pins");
    let original = config.digest().expect("actual immutable binding");
    let scorer = KevScorer::new(&config).expect("inert admitted scorer");
    assert_eq!(scorer.failure_policy(), ScorerFailurePolicy::Refuse);
    let mut changed = config.clone();
    changed.limits.inference_work += 1;
    assert_ne!(changed.digest().expect("changed declared work"), original);
    let mut excessive = config.clone();
    excessive.limits.aggregate_timeout_micros = 10_000_001;
    assert!(
        excessive.validate().is_err(),
        "RouterBinding caps aggregate scorer time at ten seconds"
    );
    let value = serde_json::to_value(&config).expect("config value");
    for (key, replacement) in [
        ("model_processing", json!(false)),
        ("development_only", json!(false)),
        ("failure_policy", json!("r0_retry")),
        ("args", json!(["-c", "pass"])),
        ("worker_sha256", json!("cc".repeat(32))),
        ("run_name", json!("dev_run")),
        ("run_name", json!("1dev")),
        ("run_name", json!("com1")),
    ] {
        let mut changed = value.clone();
        changed[key] = replacement;
        assert!(match serde_json::from_value::<KevConfig>(changed) {
            Ok(config) => config.validate().is_err(),
            Err(_) => true,
        });
    }
    fs::write(root.join("conditional.py"), b"changed projection").expect("mutate own fixture only");
    assert!(config.validate().is_err());
    fs::write(root.join("conditional.py"), b"").expect("restore exact own projection");
    config.validate().expect("original pin remains valid");
}

#[test]
fn persistent_pipe_and_cancelled_or_late_exchange_reap_only_the_owned_child() {
    let directory = tempfile::tempdir().expect("owned worker directory");
    let root = fs::canonicalize(directory.path()).expect("canonical owned worker root");
    let config = fixture_config(&root, python());
    config.validate().expect("pinned fixture interpreter");
    let digest = config.digest().expect("fixture binding");
    let (mut process, ready) = Process::spawn(&config, &digest).expect("real owned hidden child");
    assert_eq!(
        transport::wait(&ready, Instant::now() + Duration::from_secs(5), None)
            .expect("memory-free fixture ready"),
        br#"{"fixture":"memory-free"}"#
    );
    let cancellation = QueryCancellation::default();
    let allowance = QueryBudget::new(10, 1024, Duration::from_secs(5), cancellation.clone());
    for id in 1..=2 {
        let metadata = serde_json::to_vec(&ScoreRequest {
            format: FORMAT,
            operation: "score",
            id,
            config_sha256: "aa",
            input_bytes: 2,
            input_sha256: "bb",
            timeout_micros: 100_000,
        })
        .expect("fixture score metadata");
        let frame = transport::frame(&metadata, b"{}".to_vec()).expect("fixture score frame");
        let bytes = process
            .exchange(frame, Instant::now() + Duration::from_secs(1), &allowance)
            .expect("same persistent process");
        let reply: ScoreReply = serde_json::from_slice(&bytes).expect("strict real pipe reply");
        assert!(
            validate_reply(reply, id, "aa", "bb")
                .expect("matching real association")
                .is_some()
        );
    }
    let metadata = serde_json::to_vec(&ScoreRequest {
        format: FORMAT,
        operation: "score",
        id: 3,
        config_sha256: "aa",
        input_bytes: 2,
        input_sha256: "bb",
        timeout_micros: 1,
    })
    .expect("late request");
    let frame = transport::frame(&metadata, b"{}".to_vec()).expect("late frame");
    assert!(
        process
            .exchange(
                frame,
                Instant::now() + Duration::from_millis(30),
                &allowance
            )
            .is_err()
    );
    assert!(
        process.reaped(),
        "deadline stops and reaps the exact owned child"
    );
    let (tx, rx) = mpsc::channel();
    cancellation.cancel();
    tx.send(Ok(b"late".to_vec())).expect("late fixture result");
    assert!(
        transport::wait(
            &rx,
            Instant::now() + Duration::from_secs(1),
            Some(&allowance)
        )
        .is_err()
    );
    assert!(
        process
            .exchange(
                transport::frame(b"{}", vec![]).expect("control frame"),
                Instant::now() + Duration::from_secs(1),
                &allowance
            )
            .is_err()
    );
    assert!(
        process.reaped(),
        "closed worker is never restarted by failed exchange"
    );
}
