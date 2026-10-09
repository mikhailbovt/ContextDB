//! Compiler-only policy material cannot become an owner-accepted native v1 trace.

use contextdb_context::Result as ContextResult;
use contextdb_context::router::{RoutedAssembly, RouterMaterialStatus, validate_router_material};
use contextdb_recall::ProviderSnapshot;
use contextdb_service::{
    AcceptedRouterTracePort, AcceptedRouterTraceReadResult, ReadAcceptedRouterTraceRequest,
};
use contextdb_storage::{ReadSnapshot, SnapshotSelector, StorageEngine};

use super::*;

#[derive(Debug)]
struct EmptyPolicyProvider {
    snapshot: ProviderSnapshot,
    scopes: BTreeSet<String>,
    binding: AssemblyBinding,
}

impl ContextProvider for EmptyPolicyProvider {
    fn snapshot(&self) -> ContextResult<ProviderSnapshot> {
        Ok(self.snapshot.clone())
    }
    fn candidate_labels(&self) -> ContextResult<Vec<CandidatePolicyLabel>> {
        Ok(Vec::new())
    }
    fn materialize_candidate(&self, _: &BlockId) -> ContextResult<PackCandidate> {
        Err(ContextError::Provider("source-free policy fixture".into()))
    }
    fn evidence_labels(
        &self,
        requested: &[EvidenceHandle],
    ) -> ContextResult<Vec<EvidencePolicyLabel>> {
        assert!(requested.is_empty());
        Ok(Vec::new())
    }
    fn materialize_evidence(&self, _: &EvidenceHandle) -> ContextResult<PackEvidence> {
        Err(ContextError::Provider("source-free policy fixture".into()))
    }
}

impl AssemblyProvider for EmptyPolicyProvider {
    fn binding(&self) -> ContextResult<AssemblyBinding> {
        Ok(self.binding.clone())
    }
    fn dependencies(&self, _: &BlockId) -> ContextResult<EvidenceDependencies> {
        Err(ContextError::Provider("source-free policy fixture".into()))
    }
    fn verify_original(
        &self,
        _: &OriginalSourceSpan,
        _: &[u8],
        _: &mut QueryBudget,
    ) -> ContextResult<()> {
        Err(ContextError::Provider("source-free policy fixture".into()))
    }
    fn validate_read_set(
        &self,
        read_set: &AssemblyReadSet,
        _: &mut QueryBudget,
    ) -> ContextResult<()> {
        assert_eq!(read_set.binding, self.binding);
        assert_eq!(read_set.scopes, self.scopes);
        assert!(read_set.originals.is_empty());
        assert!(read_set.selected_blocks.is_empty());
        Ok(())
    }
}

fn compiler_policy_artifact(observed: &RouterEnvelope) -> RoutedAssembly {
    // A genuinely compiler-written source-free artifact supplies the unsupported
    // profile extension. It is not a matching replay artifact or a native grant.
    let mut context = observed.request.context.clone();
    context.required_facets.clear();
    let provider = EmptyPolicyProvider {
        snapshot: context.snapshot.clone(),
        scopes: context.scopes.clone(),
        binding: AssemblyBinding {
            snapshot: "synthetic-policy-fixture".into(),
            authorization: "synthetic-policy-fixture".into(),
            state: "synthetic-policy-fixture".into(),
            valid_until: None,
        },
    };
    let request = CompileAssemblyRequest {
        context,
        base: OutgoingBase {
            control: Vec::new(),
            working: Vec::new(),
            hot: Vec::new(),
            current: Vec::new(),
        },
        budget: observed.request.outgoing_budget,
    };
    let routed = ContextCompiler::new([17; 32])
        .expect("fixture compiler")
        .compile_assembly_with_router_policy(
            &request,
            &provider,
            &ReferenceTokenizer,
            &ReferenceOutgoingEncoder(&ReferenceTokenizer),
            &R0Scorer,
            &mut budget(),
        )
        .expect("actual compiler policy opt-in");
    let verification =
        validate_router_material(&routed.request, &routed.prepared_material, &mut budget())
            .expect("genuine source-free prepared policy");
    assert_eq!(
        verification.candidate_commitment,
        RouterMaterialStatus::Verified
    );
    assert!(routed.prepared_material.prepared_policy.is_some());
    routed
}

#[test]
fn native_v1_rejects_compiler_policy_before_sealing_decoding_or_prepared_acceptance() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_keys_directory, keys) = crate::encryption::tests::authority("native-v1-policy-gate");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("native-v1-policy-gate");
    let service = Arc::new(
        NativeService::open_encrypted(
            directory.path(),
            "native-v1-policy-gate",
            [7; 32],
            ledger,
            keys,
        )
        .expect("encrypted native owner"),
    );
    let fixture = planned_fixture(&service);
    let observed = envelope(&fixture.prepared);
    assert!(observed.materials.prepared_policy.is_none());
    let original = fixture
        .prepared
        .router_trace
        .as_ref()
        .expect("native v1 trace");
    let original_bytes = canonical_bytes(&observed, &mut budget()).expect("default canonical v1");
    assert_eq!(original_bytes, original.canonical_json.as_bytes());
    assert!(
        !serde_json::to_value(&observed.materials)
            .expect("legacy material")
            .as_object()
            .expect("material object")
            .contains_key("prepared_policy")
    );

    let mut extended = observed.clone();
    let artifact = compiler_policy_artifact(&observed);
    extended.materials.prepared_policy = artifact.prepared_material.prepared_policy.clone();
    let refused = |error: contextdb_service::ServiceError| {
        assert_eq!(error.code, ErrorCode::IntegrityFailure);
        assert_eq!(
            error.message,
            "native router trace v1 does not support prepared policy material"
        );
    };
    refused(
        RouterEnvelope::new(
            extended.request.clone(),
            extended.plan.clone(),
            extended.manifest.clone(),
            extended.native_view.clone(),
            extended.base.clone(),
            extended.unit_origins.clone(),
            extended.evidence_origins.clone(),
            extended.materials.clone(),
            extended.discovery.clone(),
            extended.retrieval_origins.clone(),
            extended.generic_query.clone(),
            extended.generic_discovery.clone(),
            &mut budget(),
        )
        .err()
        .expect("native v1 constructor refuses the unsupported profile"),
    );
    refused(
        service
            .prepare_router_envelope(&extended, &artifact.assembly, &mut budget())
            .expect_err("unsupported material cannot receive an owner-prepared trace"),
    );

    // Rehashing unsupported local bytes preserves no authority. The existing
    // owner seal is left untouched, so actual prepared capture must still reject.
    let mut changed = fixture.prepared.clone();
    let trace = changed.router_trace.as_mut().expect("trace");
    let text =
        canonical_bytes(&extended, &mut budget()).expect("bounded unsupported profile fixture");
    trace.trace_digest = ContentDigest::from_bytes(*blake3::hash(&text).as_bytes());
    trace.canonical_json = String::from_utf8(text).expect("canonical UTF-8");
    let parsed = prepared_envelope(trace, &mut budget());
    refused(
        parsed
            .err()
            .expect("prepared decoder refuses native v1 extension"),
    );
    let changed_request = capture_request(&fixture.source, &fixture.checkpoint, &changed);
    refused(
        decode_envelope(&changed_request.event, &mut budget())
            .err()
            .expect("captured decoder refuses native v1 extension"),
    );
    let before = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before refusal")
        .sequence();
    assert_eq!(
        service
            .capture_prepared_model_request(
                changed_request,
                &changed,
                Some(&fixture.checkpoint.receipt),
                &mut budget()
            )
            .expect_err("unsupported material has no owner seal")
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("after refusal")
            .sequence(),
        before
    );

    let accepted = publish(&service, &fixture);
    let read = service
        .read_accepted_router_trace(
            ReadAcceptedRouterTraceRequest {
                context: fixture.source.context,
                receipt: accepted.receipt,
            },
            &mut budget(),
        )
        .expect("default native v1 remains readable");
    let AcceptedRouterTraceReadResult::Complete(read) = read else {
        panic!("complete native v1")
    };
    assert!(read.material.prepared_policy.is_none());
    assert_eq!(read.header.version, contextdb_core::ROUTER_TRACE_VERSION);
    service
        .verify_native(true)
        .expect("default accepted native v1 remains valid");
}
