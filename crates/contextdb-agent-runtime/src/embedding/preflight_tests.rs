//! Fake owned process/loopback establishes protocol and cleanup, not model quality.

use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use contextdb_recall::QueryCancellation;

use super::*;

fn budget() -> QueryBudget {
    QueryBudget::new(
        500_000,
        8 * 1024 * 1024,
        Duration::from_secs(5),
        QueryCancellation::default(),
    )
}

// Re-exec only this exact test as a harmless owned process. Ordinary test runs
// return immediately; no model binary, external shell or global env change.
#[test]
fn owned_fixture_process() {
    if std::env::var_os("CONTEXTDB_EMBEDDING_TEST_CHILD").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        thread::sleep(Duration::from_secs(60));
    }
}

type Calls = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
struct Fixture {
    adapter: OwnedLocalEmbedding,
    calls: Calls,
    stopped: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(server) = self.server.take() {
            server.join().expect("bounded fixture server");
        }
    }
}

fn read_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("bounded fixture read");
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 8192);
        let mut byte = [0];
        stream.read_exact(&mut byte).expect("request header");
        header.push(byte[0]);
    }
    let header = std::str::from_utf8(&header).expect("fixture header");
    let path = header
        .lines()
        .next()
        .expect("request line")
        .split_whitespace()
        .nth(1)
        .expect("request path")
        .to_owned();
    let length: usize = header
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .expect("request size")
        .parse()
        .expect("request length");
    assert!(length <= 128 * 1024);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).expect("exact request body");
    (path, body)
}

fn fixture(token_bodies: Vec<Vec<u8>>, cancel_after_token: Option<QueryCancellation>) -> Fixture {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("fixture port");
    listener
        .set_nonblocking(true)
        .expect("bounded fixture accept");
    let port = listener.local_addr().expect("fixture address").port();
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let stopped = Arc::new(AtomicBool::new(false));
    let thread_calls = Arc::clone(&calls);
    let thread_stopped = Arc::clone(&stopped);
    let server = thread::spawn(move || {
        let mut tokens = VecDeque::from(token_bodies);
        while !thread_stopped.load(Ordering::Acquire) {
            let (mut stream, _) = match listener.accept() {
                Ok(stream) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => panic!("fixture accept: {error}"),
            };
            let (path, body) = read_request(&mut stream);
            thread_calls
                .lock()
                .expect("fixture calls")
                .push((path.clone(), body.clone()));
            let response = match path.as_str() {
                "/props" => serde_json::to_vec(&serde_json::json!({
                    "build_info":"b10964-b29c606e", "model_path":"fixture.gguf", "total_slots":1,
                    "default_generation_settings":{"n_ctx":4096}
                }))
                .expect("fixture props"),
                "/tokenize" => {
                    let request: serde_json::Value =
                        serde_json::from_slice(&body).expect("token request");
                    assert_eq!(request["add_special"], true);
                    assert_eq!(request["parse_special"], false);
                    assert_eq!(request["with_pieces"], false);
                    if let Some(cancellation) = &cancel_after_token {
                        cancellation.cancel();
                    }
                    tokens.pop_front().expect("declared tokenizer response")
                }
                "/v1/embeddings" => {
                    let request: serde_json::Value =
                        serde_json::from_slice(&body).expect("embedding request");
                    let count = request["input"]
                        .as_array()
                        .expect("exact token-array inference")
                        .len();
                    let mut values = vec![0.0_f32; 1024];
                    values[0] = 1.0;
                    serde_json::to_vec(
                        &serde_json::json!({"object":"list", "model":"contextdb-qwen3-06b-q8",
                        "data":[{"index":0,"object":"embedding","embedding":values}],
                        "usage":{"prompt_tokens":count,"total_tokens":count}}),
                    )
                    .expect("fixture embedding")
                }
                _ => panic!("unexpected endpoint {path}"),
            };
            stream
                .set_write_timeout(Some(Duration::from_secs(1)))
                .expect("bounded fixture write");
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                response.len()
            );
            // Cancellation or a rejected declared length may close the client.
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&response);
        }
    });
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args([
            "--exact",
            "embedding::preflight_tests::owned_fixture_process",
        ])
        .env("CONTEXTDB_EMBEDDING_TEST_CHILD", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let child = command.spawn().expect("harmless owned fixture child");
    let adapter = OwnedLocalEmbedding {
        profile: TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(ContentDigest::from_bytes(
            [3; 32],
        )),
        model_path: "fixture.gguf".into(),
        port,
        backend: Mutex::new(Some(Backend { child: Some(child) })),
    };
    Fixture {
        adapter,
        calls,
        stopped,
        server: Some(server),
    }
}
fn tokens(values: &[i32]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"tokens":values})).expect("fixture tokens")
}
fn neural_calls(fixture: &Fixture) -> usize {
    fixture
        .calls
        .lock()
        .expect("calls")
        .iter()
        .filter(|(path, _)| path == "/v1/embeddings")
        .count()
}

#[test]
fn measured_oversize_keeps_owned_backend_and_permits_a_later_exact_valid_forward() {
    let fixture = fixture(
        vec![
            tokens(&vec![7; 2049]),
            tokens(&[3, 4, 5]),
            tokens(&[3, 4, 5]),
        ],
        None,
    );
    let text = " Не меняй Регистр. 😀 ";
    let measured = fixture
        .adapter
        .measure_tokens(EmbeddingTextKind::Query, text, &mut budget())
        .expect("bounded oversize observation");
    measured
        .validate(
            fixture.adapter.profile(),
            EmbeddingTextKind::Query,
            text,
            &mut budget(),
        )
        .expect("exact query measurement binding");
    assert_eq!(measured.token_count, 2049);
    assert!(
        !measured
            .fits_inference_limit(fixture.adapter.profile(), &mut budget())
            .expect("profile-bound capacity")
    );
    assert!(fixture.adapter.backend.lock().expect("backend").is_some());
    assert_eq!(
        neural_calls(&fixture),
        0,
        "measurement performs no neural forward"
    );
    let fitting = fixture
        .adapter
        .measure_tokens(EmbeddingTextKind::Source, "valid", &mut budget())
        .expect("same backend valid preflight");
    assert!(
        fitting
            .fits_inference_limit(fixture.adapter.profile(), &mut budget())
            .expect("valid capacity")
    );
    assert_eq!(neural_calls(&fixture), 0);
    let embedded = fixture
        .adapter
        .embed(EmbeddingTextKind::Source, "valid", &mut budget())
        .expect("later explicit valid inference");
    assert_eq!(embedded.tokens_digest, fitting.tokens_digest);
    assert_eq!(embedded.token_count, fitting.token_count);
    assert_eq!(neural_calls(&fixture), 1);
    let calls = fixture.calls.lock().expect("calls");
    let tokenize = calls
        .iter()
        .find(|(path, _)| path == "/tokenize")
        .expect("query tokenization");
    let request: serde_json::Value =
        serde_json::from_slice(&tokenize.1).expect("actual token body");
    assert_eq!(
        request["content"],
        fixture
            .adapter
            .profile()
            .input_text(EmbeddingTextKind::Query, text)
            .expect("actual query template")
    );
    let inference = calls
        .iter()
        .find(|(path, _)| path == "/v1/embeddings")
        .expect("explicit inference");
    let request: serde_json::Value =
        serde_json::from_slice(&inference.1).expect("actual inference body");
    assert_eq!(request["input"], serde_json::json!([3, 4, 5]));
}

#[test]
fn strict_embedding_oversize_still_closes_without_neural_forward() {
    let fixture = fixture(vec![tokens(&vec![7; 2049])], None);
    assert_eq!(
        fixture
            .adapter
            .embed(EmbeddingTextKind::Source, "oversize", &mut budget())
            .expect_err("strict inference cap")
            .code,
        ErrorCode::InvalidArgument
    );
    assert!(
        fixture
            .adapter
            .backend
            .lock()
            .expect("closed backend")
            .is_none()
    );
    assert_eq!(neural_calls(&fixture), 0);
}

#[test]
fn malformed_and_hard_capped_measurement_responses_close_before_inference() {
    let bounded = fixture(
        vec![tokens(&vec![0; MAX_MEASURED_EMBEDDING_TOKENS as usize])],
        None,
    );
    let measured = bounded
        .adapter
        .measure_tokens(EmbeddingTextKind::Source, "source", &mut budget())
        .expect("exact observation ceiling remains a measurement");
    assert_eq!(measured.token_count, MAX_MEASURED_EMBEDDING_TOKENS);
    assert!(
        bounded
            .adapter
            .backend
            .lock()
            .expect("bounded live backend")
            .is_some()
    );
    assert_eq!(neural_calls(&bounded), 0);
    drop(bounded);
    for body in [
        tokens(&[]),
        tokens(&[-1]),
        tokens(&vec![0; MAX_MEASURED_EMBEDDING_TOKENS as usize + 1]),
        br#"{"tokens":[1],"unexpected":1}"#.to_vec(),
        vec![b' '; 128 * 1024 + 1],
    ] {
        let fixture = fixture(vec![body], None);
        assert_eq!(
            fixture
                .adapter
                .measure_tokens(EmbeddingTextKind::Source, "source", &mut budget())
                .expect_err("bounded malformed/token-count/body refusal")
                .code,
            ErrorCode::InvalidArgument
        );
        assert!(
            fixture
                .adapter
                .backend
                .lock()
                .expect("closed backend")
                .is_none()
        );
        assert_eq!(neural_calls(&fixture), 0);
    }
}

#[test]
fn cancelled_token_response_and_preallocation_refusal_close_without_forward() {
    let cancellation = QueryCancellation::default();
    let fixture = fixture(vec![tokens(&[1, 2])], Some(cancellation.clone()));
    let mut allowance = QueryBudget::new(
        500_000,
        8 * 1024 * 1024,
        Duration::from_secs(5),
        cancellation,
    );
    assert_eq!(
        fixture
            .adapter
            .measure_tokens(EmbeddingTextKind::Query, "query", &mut allowance)
            .expect_err("shared cancellation during tokenization")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert!(
        fixture
            .adapter
            .backend
            .lock()
            .expect("closed backend")
            .is_none()
    );
    assert_eq!(neural_calls(&fixture), 0);
    let fixture = self::fixture(vec![], None);
    let mut allowance = QueryBudget::new(
        100_000,
        0,
        Duration::from_secs(5),
        QueryCancellation::default(),
    );
    assert_eq!(
        fixture
            .adapter
            .measure_tokens(EmbeddingTextKind::Query, "query", &mut allowance)
            .expect_err("before input allocation or HTTP")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert!(fixture.calls.lock().expect("calls").is_empty());
    assert!(
        fixture
            .adapter
            .backend
            .lock()
            .expect("closed backend")
            .is_none()
    );
}

#[test]
fn token_observation_rejects_changed_bindings_and_old_implementers_are_unsupported() {
    let fixture = fixture(vec![tokens(&[1, 2, 3])], None);
    let measured = fixture
        .adapter
        .measure_tokens(EmbeddingTextKind::Query, "query", &mut budget())
        .expect("measurement");
    for (kind, text) in [
        (EmbeddingTextKind::Source, "query"),
        (EmbeddingTextKind::Query, " query"),
    ] {
        assert!(
            measured
                .validate(fixture.adapter.profile(), kind, text, &mut budget())
                .is_err()
        );
    }
    let mut changed = fixture.adapter.profile().clone();
    changed.backend_artifacts_digest = ContentDigest::from_bytes([4; 32]);
    assert!(
        measured
            .validate(&changed, EmbeddingTextKind::Query, "query", &mut budget())
            .is_err()
    );
    assert!(
        measured
            .fits_inference_limit(&changed, &mut budget())
            .is_err()
    );
    for count in [0, MAX_MEASURED_EMBEDDING_TOKENS + 1] {
        let invalid = TokenizedText {
            token_count: count,
            ..measured.clone()
        };
        assert!(
            invalid
                .validate(
                    fixture.adapter.profile(),
                    EmbeddingTextKind::Query,
                    "query",
                    &mut budget()
                )
                .is_err()
        );
    }
    let mut wire = serde_json::to_value(&measured).expect("typed measurement wire");
    wire["token_count"] = serde_json::json!(u64::from(u32::MAX) + 1);
    assert!(
        serde_json::from_value::<TokenizedText>(wire).is_err(),
        "integer count overflow is refused"
    );
    #[derive(Debug)]
    struct Legacy(TextEmbeddingProfile);
    impl TextEmbeddingAdapter for Legacy {
        fn profile(&self) -> &TextEmbeddingProfile {
            &self.0
        }
        fn embed(
            &self,
            _: EmbeddingTextKind,
            _: &str,
            _: &mut QueryBudget,
        ) -> ServiceResult<EmbeddedText> {
            Err(ServiceError::new(
                ErrorCode::Unsupported,
                "fixture has no neural adapter",
                false,
            ))
        }
    }
    let legacy = Legacy(fixture.adapter.profile().clone());
    assert_eq!(
        legacy
            .measure_tokens(EmbeddingTextKind::Query, "query", &mut budget())
            .expect_err("no implicit fallback for an old implementer")
            .code,
        ErrorCode::Unsupported
    );
}
