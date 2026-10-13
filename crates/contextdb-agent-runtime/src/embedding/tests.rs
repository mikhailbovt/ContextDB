use std::{
    io::{Read, Write},
    net::TcpListener,
};

use contextdb_recall::QueryCancellation;

use super::*;

fn budget(bytes: u64) -> QueryBudget {
    QueryBudget::new(
        100_000,
        bytes,
        Duration::from_secs(2),
        QueryCancellation::default(),
    )
}

#[test]
fn profile_and_exact_text_bindings_refuse_changed_input_role_vector_and_backend() {
    let profile =
        TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(ContentDigest::from_bytes([3; 32]));
    let text = " Верни Фразу.\nİSTANBUL 😀 ";
    let input = profile
        .input_text(EmbeddingTextKind::Query, text)
        .expect("query template");
    assert_eq!(
        input,
        format!(
            "Instruct: Retrieve conversation originals relevant to the question.\nQuery: {text}"
        )
    );
    assert_eq!(
        profile
            .input_text(EmbeddingTextKind::Source, text)
            .expect("identity document"),
        text
    );
    let mut values = vec![0.0; 1024];
    values[0] = 1.0;
    let mut hash = blake3::Hasher::new();
    for value in &values {
        hash.update(&f32::to_le_bytes(*value));
    }
    let result = EmbeddedText {
        profile_digest: profile.digest().expect("profile digest"),
        kind: EmbeddingTextKind::Query,
        text_digest: digest(text.as_bytes()),
        input_digest: digest(input.as_bytes()),
        tokens_digest: ContentDigest::from_bytes([4; 32]),
        token_count: 30,
        values,
        vector_digest: ContentDigest::from_bytes(*hash.finalize().as_bytes()),
    };
    result
        .validate(
            &profile,
            EmbeddingTextKind::Query,
            text,
            &mut budget(1_000_000),
        )
        .expect("bound result");
    assert!(
        result
            .validate(
                &profile,
                EmbeddingTextKind::Source,
                text,
                &mut budget(1_000_000)
            )
            .is_err()
    );
    assert!(
        result
            .validate(
                &profile,
                EmbeddingTextKind::Query,
                text.trim(),
                &mut budget(1_000_000)
            )
            .is_err()
    );
    let mut corrupted = result.clone();
    corrupted.values[0] = 0.0;
    assert!(
        corrupted
            .validate(
                &profile,
                EmbeddingTextKind::Query,
                text,
                &mut budget(1_000_000)
            )
            .is_err()
    );
    corrupted.values[0] = f32::NAN;
    assert!(
        corrupted
            .validate(
                &profile,
                EmbeddingTextKind::Query,
                text,
                &mut budget(1_000_000)
            )
            .is_err()
    );
    let mut changed = profile.clone();
    changed.backend_artifacts_digest = ContentDigest::from_bytes([5; 32]);
    assert_ne!(
        profile.vector_space_id().expect("space"),
        changed.vector_space_id().expect("changed space")
    );
    assert!(
        result
            .validate(
                &changed,
                EmbeddingTextKind::Query,
                text,
                &mut budget(1_000_000)
            )
            .is_err()
    );
    assert_eq!(
        result
            .validate(&profile, EmbeddingTextKind::Query, text, &mut budget(0))
            .expect_err("no allocation allowance")
            .code,
        ErrorCode::BudgetExhausted
    );
}

#[test]
fn manifest_rejects_path_escape_and_unpinned_dynamic_library() {
    let dir = tempfile::tempdir().expect("runtime directory");
    std::fs::write(dir.path().join("server.exe"), b"server").expect("fixture server");
    std::fs::write(dir.path().join("UNPINNED.DLL"), b"dll").expect("fixture library");
    let config = LocalEmbeddingConfig {
        program: dir.path().join("server.exe"),
        model: dir.path().join("weights.gguf"),
        runtime_artifacts: BTreeMap::from([("server.exe".into(), "a".repeat(64))]),
        port: 1,
    };
    std::fs::write(&config.model, b"weights").expect("fixture weights");
    let profile = TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(
        embedding_backend_artifacts_digest(&config.runtime_artifacts).expect("bounded manifest"),
    );
    assert_eq!(
        assets::verify(&config, &profile, &mut budget(1_000_000))
            .expect_err("unlisted DLL before launch")
            .code,
        ErrorCode::InvalidArgument
    );
    assert!(
        embedding_backend_artifacts_digest(&BTreeMap::from([(
            "../server.exe".into(),
            "a".repeat(64)
        )]))
        .is_err()
    );
}

#[test]
fn local_http_reads_only_bounded_exact_body_and_propagates_cancellation() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("fixture listener");
    let port = listener.local_addr().expect("fixture address").port();
    let fixture = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request");
        let mut request = [0; 512];
        let _ = stream.read(&mut request).expect("request bytes");
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            )
            .expect("bounded response");
    });
    assert_eq!(
        http::request(port, "GET", "/props", &[], 2, &mut budget(20_000)).expect("bounded body"),
        b"{}"
    );
    fixture.join().expect("fixture done");
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(10, 10, Duration::from_secs(2), cancellation);
    assert_eq!(
        http::request(port, "GET", "/props", &[], 2, &mut cancelled)
            .expect_err("before IO")
            .code,
        ErrorCode::BudgetExhausted
    );
}

#[test]
fn local_http_wait_does_not_reset_parent_deadline() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("fixture listener");
    listener
        .set_nonblocking(true)
        .expect("fixture accept is releasable before IO");
    let port = listener.local_addr().expect("fixture address").port();
    let (release, released) = std::sync::mpsc::channel();
    let fixture = thread::spawn(move || {
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    // The parent may already expire before its first connect
                    // when the scheduler pauses it. That must not strand join.
                    if released.try_recv().is_ok() {
                        return;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("fixture accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("bounded fixture read");
        let mut request = [0; 512];
        let _ = stream.read(&mut request);
        // Keep this response pending until the parent observes its deadline.
        // The watchdog only ends a broken client; it never supplies a response.
        released
            .recv_timeout(Duration::from_secs(2))
            .expect("parent deadline release");
    });
    let mut allowance = QueryBudget::new(
        10_000,
        1_000_000,
        Duration::from_millis(20),
        QueryCancellation::default(),
    );
    assert_eq!(
        http::request(port, "GET", "/props", &[], 2, &mut allowance)
            .expect_err("parent deadline")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert!(matches!(
        allowance.check(),
        Err(contextdb_recall::QueryLimit::Deadline)
    ));
    assert_eq!(
        http::request(port, "GET", "/props", &[], 2, &mut allowance)
            .expect_err("same expired allowance cannot start another request")
            .code,
        ErrorCode::BudgetExhausted
    );
    release.send(()).expect("release blocked fixture");
    fixture.join().expect("fixture done");
}

#[test]
#[ignore = "requires explicitly provisioned pinned local GPU assets"]
fn real_pinned_local_encoder_exact_tokens_cold_launch_and_oversize_refusal() {
    let path = std::env::var_os("CONTEXTDB_EMBEDDING_CONFIG").expect("explicit pinned host config");
    let bytes = std::fs::read(path).expect("provisioned config");
    assert!(bytes.len() < 64 * 1024);
    let config: LocalEmbeddingConfig = serde_json::from_slice(&bytes).expect("fixed config");
    let startup = || {
        QueryBudget::new(
            1_000_000,
            4 * 1024 * 1024 * 1024,
            Duration::from_secs(120),
            QueryCancellation::default(),
        )
    };
    let request = || {
        QueryBudget::new(
            100_000,
            8 * 1024 * 1024,
            Duration::from_secs(15),
            QueryCancellation::default(),
        )
    };
    let source =
        "Для фонаря в пещере выбрали янтарное стекло; запасные аккумуляторы лежат у входа.";
    let query = "Где оставили дополнительные источники питания для подземного освещения?";
    let mut adapter =
        OwnedLocalEmbedding::launch(&config, &mut startup()).expect("verified owned GPU backend");
    let first = adapter
        .embed(EmbeddingTextKind::Source, source, &mut request())
        .expect("source exact tokens");
    let query_vector = adapter
        .embed(EmbeddingTextKind::Query, query, &mut request())
        .expect("query exact tokens");
    first
        .validate(
            adapter.profile(),
            EmbeddingTextKind::Source,
            source,
            &mut request(),
        )
        .expect("exact source receipt");
    let profile_digest = first.profile_digest;
    let similarity: f64 = first
        .values
        .iter()
        .zip(&query_vector.values)
        .map(|(a, b)| f64::from(*a) * f64::from(*b))
        .sum();
    assert!(similarity.is_finite());
    let source_tokens = first.token_count;
    let query_tokens = query_vector.token_count;
    adapter
        .shutdown(&mut request())
        .expect("separate bounded process cleanup");
    drop(adapter);
    let mut cold =
        OwnedLocalEmbedding::launch(&config, &mut startup()).expect("fresh owned process");
    let second = cold
        .embed(EmbeddingTextKind::Source, source, &mut request())
        .expect("cold exact source");
    assert_eq!(second.profile_digest, profile_digest);
    assert_eq!(second.token_count, source_tokens);
    let cold_similarity: f64 = first
        .values
        .iter()
        .zip(&second.values)
        .map(|(a, b)| f64::from(*a) * f64::from(*b))
        .sum();
    assert!((cold_similarity - 1.0).abs() < 0.001);
    // Below byte limit, above exact token limit; no backend truncation is accepted.
    let oversized = "x|".repeat(2200);
    assert!(oversized.len() < cold.profile().max_text_bytes as usize);
    let oversized_measurement = cold
        .measure_tokens(EmbeddingTextKind::Source, &oversized, &mut request())
        .expect("bounded oversize token measurement without inference");
    assert!(oversized_measurement.token_count > cold.profile().max_input_tokens);
    assert!(
        !oversized_measurement
            .fits_inference_limit(cold.profile(), &mut request())
            .expect("exact profile-bound oversize")
    );
    assert!(
        cold.backend
            .lock()
            .expect("still live measured backend")
            .is_some()
    );
    let error = cold
        .embed(EmbeddingTextKind::Source, &oversized, &mut request())
        .expect_err("too many tokens before inference");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(cold.backend.lock().expect("closed owned backend").is_none());
    cold.shutdown(&mut request())
        .expect("already closed encoder cleanup");
    println!(
        "{}",
        serde_json::json!({"profile_digest":profile_digest,"source_tokens":source_tokens,"query_tokens":query_tokens,"dimensions":first.values.len(),"source_vector_digest":first.vector_digest,"cold_vector_digest":second.vector_digest,"query_source_cosine_observation":similarity,"cold_source_cosine":cold_similarity,"oversized_measured_tokens":oversized_measurement.token_count,"oversized_token_input_refused":true,"retrieval_quality_evaluated":false})
    );
}
