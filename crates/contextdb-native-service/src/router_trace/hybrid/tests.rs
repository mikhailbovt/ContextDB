//! Pure retained-observation checks, not tokenizer or neural-quality evidence.
use super::*;
use contextdb_context::{OutgoingMessage, OutgoingRole, OutgoingZone, VisibleOriginal};
use contextdb_core::{ModelCallId, WorkspaceId};
use contextdb_recall::QueryCancellation;
use contextdb_service::CaptureDurability;
use std::time::Duration;

fn budget() -> QueryBudget {
    QueryBudget::new(
        20_000_000,
        64 * 1024 * 1024,
        Duration::from_secs(30),
        QueryCancellation::default(),
    )
}
fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}

fn base() -> OutgoingBase {
    let current = (0..8)
        .map(|index| {
            let text = format!(
                "Current message {index}: {}.\n",
                "Meaningful original words. ".repeat(14)
            );
            let source = OriginalSourceSpan {
                event_id: ObservationId::new(),
                payload_digest: digest(text.as_bytes()),
                start: 0,
                end: text.len() as u64,
                span_digest: digest(text.as_bytes()),
            };
            OutgoingMessage {
                id: BlockId::new(format!("current/{index}")).expect("fixed ID"),
                zone: OutgoingZone::CurrentTurn,
                role: OutgoingRole::User,
                originals: vec![VisibleOriginal {
                    span: source,
                    text_start: 0,
                    text_end: text.len() as u64,
                }],
                text,
                tool_calls: Vec::new(),
                tool_result: None,
            }
        })
        .collect();
    OutgoingBase {
        current,
        working: Vec::new(),
        hot: Vec::new(),
        control: Vec::new(),
    }
}

fn tokens(profile: &TextEmbeddingProfile, cues: &DenseQueryCues, count: u32) -> TokenizedText {
    TokenizedText {
        profile_digest: profile.digest().expect("fixed profile"),
        kind: EmbeddingTextKind::Query,
        text_digest: cues.text_digest,
        input_digest: digest(
            profile
                .input_text(EmbeddingTextKind::Query, &cues.text)
                .expect("bounded input")
                .as_bytes(),
        ),
        tokens_digest: digest(&count.to_le_bytes()),
        token_count: count,
    }
}

fn observation(base: &OutgoingBase) -> OwnedHybridObservation {
    let profile = TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(digest(
        b"fixture artifacts; no encoder called",
    ));
    let mut preflights = Vec::new();
    for (limit, count) in [(4096, 3000), (2048, 100)] {
        let cues = dense_step_query_with_byte_limit(base, limit, &mut budget())
            .expect("actual shared sampler");
        let measured = tokens(&profile, &cues, count);
        preflights.push(
            HybridPreflightObservation::from_sample(limit as u32, &cues, measured, &mut budget())
                .expect("exact observation"),
        );
    }
    let last = &preflights.last().expect("finite preflight").tokens;
    let vector = HybridVectorReceipt {
        profile_digest: last.profile_digest,
        kind: last.kind,
        text_digest: last.text_digest,
        input_digest: last.input_digest,
        tokens_digest: last.tokens_digest,
        token_count: last.token_count,
        vector_digest: digest(b"fixture receipt; no forward called"),
    };
    let checkpoint_digest = digest(b"fixture checkpoint");
    let mut routes = Vec::new();
    for route in [
        HybridRouteKind::Bm25,
        HybridRouteKind::Dense,
        HybridRouteKind::Causal,
    ] {
        routes.push(HybridRouteObservation {
            route,
            admitted_sources: BTreeSet::new(),
            ranked_sources: 0,
            completion: HybridCompletion::Complete,
            source_coverage_incomplete: false,
            raw_lag: false,
            dense_lag: false,
            tail_witness_complete: route == HybridRouteKind::Dense,
            tail_scoring_complete: route == HybridRouteKind::Dense,
            node_reads: 0,
            vector_reads: 0,
            discovered: 0,
            tail_vector_reads: 0,
            dense_witness: (route == HybridRouteKind::Dense).then(|| HybridDenseWitness {
                graph_digest: digest(b"fixture immutable graph"),
                observed_dense_commitment: digest(b"fixture accepted complete prefix"),
                proven_dense_commitment: digest(b"fixture accepted complete prefix"),
                base_through: 1,
                observed_dense_through: 2,
                proven_through: 2,
                raw_through: 2,
            }),
            segmented_dense_witness: None,
        });
    }
    OwnedHybridObservation {
        revision: HYBRID_OBSERVATION_REVISION.into(),
        intent: OwnedHybridIntent {
            call_id: ModelCallId::new(),
            request_event: ObservationId::new(),
            interaction_sequence: 1,
            attempt: 0,
            limits: Default::default(),
        },
        checkpoint_receipt: CaptureReceipt {
            domain: NATIVE_CAPTURE_DOMAIN.into(),
            database_id: "fixture-native".into(),
            workspace_id: WorkspaceId::new(),
            event_id: ObservationId::new(),
            workspace_commit: 1,
            event_digest: digest(b"fixture envelope"),
            payload_digest: Some(checkpoint_digest),
            durability: CaptureDurability::Sync,
            token: "fixture-not-a-native-grant".into(),
        },
        checkpoint_digest,
        checkpoint_revision: 1,
        pack_id: ContextPackId::new(),
        known_at: 2,
        authorization_epoch: 0,
        input_base_digest: contextdb_context::router::canonical_digest(base, &mut budget())
            .expect("bounded base"),
        base_digest: contextdb_context::router::canonical_digest(base, &mut budget())
            .expect("bounded base"),
        profile_digest: profile.digest().expect("fixed profile"),
        embedding_profile: profile,
        sampler_revision: DENSE_QUERY_REFINEMENT_REVISION.into(),
        fusion_revision: HYBRID_FUSION_REVISION.into(),
        preflights,
        vector,
        routes,
        selected: Vec::new(),
        ranked_out: false,
    }
}

#[test]
fn exact_sampler_replay_binds_refined_away_sources_and_first_fit_token_receipt() {
    let base = base();
    let original = observation(&base);
    let origins: BTreeSet<_> = original
        .preflights
        .iter()
        .flat_map(|p| p.fragments.iter().map(|f| f.source.event_id))
        .collect();
    original
        .validate_shape(&mut budget())
        .expect("bounded observations");
    original
        .validate_preflights(&base, &origins, &mut budget())
        .expect("actual deterministic sample replay");
    let final_sources: BTreeSet<_> = original.preflights[1]
        .fragments
        .iter()
        .map(|f| f.source.event_id)
        .collect();
    assert!(
        origins.difference(&final_sources).next().is_some(),
        "fixture actually refines away already tokenized sources"
    );
    assert!(
        original
            .validate_preflights(&base, &final_sources, &mut budget())
            .is_err()
    );
    let mut changed = original.clone();
    changed.preflights[0].tokens.token_count = 100;
    assert!(
        changed
            .validate_preflights(&base, &origins, &mut budget())
            .is_err(),
        "cannot tokenize more after first fit"
    );
    let mut changed = original.clone();
    changed.vector.tokens_digest = digest(b"other exact input tokens");
    assert!(
        changed
            .validate_preflights(&base, &origins, &mut budget())
            .is_err()
    );
    let mut changed = original.clone();
    changed.preflights[0].fragments[0].source.event_id = ObservationId::new();
    assert!(
        changed
            .validate_preflights(&base, &origins, &mut budget())
            .is_err(),
        "equal bytes do not permit source identity substitution"
    );
    let mut changed = original;
    changed.preflights[0].byte_limit = 2048;
    assert!(
        changed
            .validate_preflights(&base, &origins, &mut budget())
            .is_err()
    );
}

#[test]
fn source_rrf_receipt_rejects_lost_frontier_duplicate_votes_and_false_completion() {
    let mut original = observation(&base());
    let a = ObservationId::new();
    let b = ObservationId::new();
    let origins = BTreeSet::from([a, b]);
    original.routes[0].admitted_sources = origins.clone();
    original.routes[0].ranked_sources = 2;
    original.routes[1].admitted_sources = BTreeSet::from([a]);
    original.routes[1].ranked_sources = 1;
    original.selected = vec![
        HybridSelectedSource {
            event_id: a,
            routing_micros: 2 * (1_000_000 / 61),
            route_ranks: vec![
                HybridRouteRank {
                    route: HybridRouteKind::Bm25,
                    rank: 1,
                },
                HybridRouteRank {
                    route: HybridRouteKind::Dense,
                    rank: 1,
                },
            ],
        },
        HybridSelectedSource {
            event_id: b,
            routing_micros: 1_000_000 / 62,
            route_ranks: vec![HybridRouteRank {
                route: HybridRouteKind::Bm25,
                rank: 2,
            }],
        },
    ];
    original
        .validate_routes(&origins, &mut budget())
        .expect("actual fixed integer vote arithmetic");
    assert!(
        original
            .validate_routes(&BTreeSet::from([a]), &mut budget())
            .is_err(),
        "discarded supplier stays in closure"
    );
    let mut changed = original.clone();
    changed.selected[1].route_ranks[0].rank = 1;
    assert!(changed.validate_routes(&origins, &mut budget()).is_err());
    let mut changed = original.clone();
    changed.routes[1].tail_witness_complete = false;
    assert!(changed.validate_routes(&origins, &mut budget()).is_err());
    let mut changed = original.clone();
    changed.routes[1].vector_reads = u64::from(changed.intent.limits.vector_reads) + 1;
    assert!(changed.validate_routes(&origins, &mut budget()).is_err());
    let mut changed = original;
    changed.selected[0].routing_micros += 1;
    assert!(changed.validate_routes(&origins, &mut budget()).is_err());
}

#[test]
fn existing_trace_constructor_keeps_absent_hybrid_encoding_and_refuses_v1_attach() {
    use crate::router_trace::tests::{envelope, prepare, prepare_catalog, request, source};
    use contextdb_service::CapturePort;
    let directory = tempfile::tempdir().expect("native directory");
    let (_authority, ledger) = crate::suppression::tests::authority("trace-absent-hybrid");
    let service = crate::NativeService::open_with_suppression(
        directory.path(),
        "trace-absent-hybrid",
        [7; 32],
        ledger,
    )
    .expect("actual existing native owner");
    let original = source(1, "Existing trace remains free of hybrid metadata.");
    service
        .append_event(original.clone())
        .expect("actual capture");
    prepare_catalog(&service, &original, false);
    let prepared = prepare(&service, request(&original));
    let trace = prepared
        .router_trace
        .as_ref()
        .expect("existing required trace");
    let retained: serde_json::Value =
        serde_json::from_str(&trace.canonical_json).expect("bounded canonical JSON");
    assert!(retained.get("owned_hybrid").is_none());
    let mut retained = envelope(&prepared);
    assert!(retained.owned_hybrid.is_none());
    assert!(
        retained
            .attach_hybrid_query(observation(&base()), &mut budget())
            .is_err(),
        "v1 cannot acquire a hybrid observation"
    );
    assert!(retained.owned_hybrid.is_none(), "failed attach is atomic");
}

#[test]
fn dense_witness_keeps_observed_prefix_distinct_from_proven_base_and_lag() {
    let original = observation(&base());
    let origins = BTreeSet::new();
    original
        .validate_routes(&origins, &mut budget())
        .expect("complete protected witness");
    let mut partial = original.clone();
    let dense = &mut partial.routes[1];
    dense.completion = HybridCompletion::TailWorkLimit;
    dense.tail_witness_complete = false;
    dense.tail_scoring_complete = false;
    let witness = dense.dense_witness.as_mut().expect("dense-only witness");
    witness.proven_through = witness.base_through;
    witness.proven_dense_commitment = digest(b"fixture immutable base commitment");
    partial
        .validate_routes(&origins, &mut budget())
        .expect("honest base-only incomplete witness");
    let mut forged = partial.clone();
    forged.routes[1]
        .dense_witness
        .as_mut()
        .expect("witness")
        .proven_through = 2;
    assert!(
        forged.validate_routes(&origins, &mut budget()).is_err(),
        "partial witness cannot claim observed cutoff"
    );
    let mut forged = original.clone();
    forged.routes[1]
        .dense_witness
        .as_mut()
        .expect("witness")
        .proven_dense_commitment = digest(b"different prefix at identical cutoff");
    assert!(forged.validate_routes(&origins, &mut budget()).is_err());
    let mut lag = original.clone();
    lag.routes[1].completion = HybridCompletion::DenseLag;
    lag.routes[1].dense_lag = true;
    lag.known_at = 3;
    lag.routes[1]
        .dense_witness
        .as_mut()
        .expect("witness")
        .raw_through = 3;
    lag.validate_routes(&origins, &mut budget())
        .expect("observed dense lag kept explicit");
    let mut forged = lag.clone();
    forged.routes[1].dense_lag = false;
    assert!(forged.validate_routes(&origins, &mut budget()).is_err());
    let mut forged = lag;
    forged.known_at = 2;
    assert!(
        forged.validate_routes(&origins, &mut budget()).is_err(),
        "no future cutoff"
    );
    let mut forged = original.clone();
    forged.routes[1].dense_witness = None;
    assert!(forged.validate_routes(&origins, &mut budget()).is_err());
    let mut forged = original;
    forged.routes[0].dense_witness = forged.routes[1].dense_witness.clone();
    assert!(
        forged.validate_routes(&origins, &mut budget()).is_err(),
        "non-dense route cannot relabel index witness"
    );
}

#[test]
fn feature_marker_reads_complete_bounded_pages_without_treating_nested_keys_as_observations() {
    use crate::router_trace::tests::{prepare, prepare_catalog, request, source};
    use contextdb_context::{ReferenceOutgoingEncoder, ReferenceTokenizer};
    use contextdb_service::CapturePort;
    let directory = tempfile::tempdir().expect("native directory");
    let (_authority, ledger) = crate::suppression::tests::authority("hybrid-marker-pages");
    let service = crate::NativeService::open_with_suppression(
        directory.path(),
        "hybrid-marker-pages",
        [7; 32],
        ledger,
    )
    .expect("existing owner");
    let mut original = source(1, "Public marker fixture original.");
    service
        .append_event(original.clone())
        .expect("actual captured original");
    prepare_catalog(&service, &original, false);
    let prepared = prepare(&service, request(&original));
    let call = ModelCallId::new();
    let mut manifest = ReferenceOutgoingEncoder(&ReferenceTokenizer)
        .capture_manifest(call, &prepared.messages, &prepared.outgoing, &mut budget())
        .expect("actual wire manifest");
    let header = prepared.router_trace.as_ref().expect("protected metadata");
    for (json, expected, paged) in [
        (
            format!(
                "{{\"padding\":\"{}\",\"owned_hybrid\":{{}}}}",
                "z".repeat(contextdb_core::MAX_ROUTER_TRACE_PAGE_BYTES - 16)
            ),
            true,
            true,
        ),
        ("{\"padding\":{\"owned_hybrid\":{}}}".into(), false, false),
        ("{\"owned_hybrid\":null}".into(), false, false),
    ] {
        let trace = contextdb_core::RouterTraceAttachment::new_with_version(
            contextdb_core::ROUTER_REPLAY_TRACE_VERSION,
            call,
            header.pack_id,
            manifest.wire_digest,
            manifest.byte_length,
            header.router_request_digest,
            header.router_plan_digest,
            header.router_manifest_digest,
            header.origin_closure_digest,
            &json,
        )
        .expect("bounded marker-only attachment; not a native observation proof");
        if paged {
            assert_eq!(trace.pages.len(), 2);
        }
        manifest.router_trace = Some(Box::new(trace));
        original.event.payload = EventPayload::Assembly {
            manifest: manifest.clone(),
        };
        assert_eq!(
            event_has_hybrid(&original.event).expect("complete streaming marker"),
            expected
        );
    }
}
