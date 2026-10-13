//! Byte compatibility and actual cold native configuration admission.

use std::sync::Arc;

use contextdb_native_service::{
    CustodyMasterKey, NativeCustodyKeys, NativeService, NativeSuppressionLedger,
};
use serde_json::{Value, json};

use super::*;
use crate::TokenKey;
use crate::owned_conversation::{authority, binding};

fn config(profile: Option<RouterTraceProfile>) -> HostConfig {
    let mut value = json!({
        "schema_version":1,
        "identity":{
            "workspace_id":"10000000-0000-4000-8000-000000000001",
            "session_id":"10000000-0000-4000-8000-000000000002",
            "run_id":"10000000-0000-4000-8000-000000000003",
            "actor_id":"10000000-0000-4000-8000-000000000004",
            "agent_id":"10000000-0000-4000-8000-000000000005",
            "subject_id":"10000000-0000-4000-8000-000000000006",
            "scopes":["10000000-0000-4000-8000-000000000007"]
        },
        "control":"Use attributed captured conversation context.",
        "input_tokens":2048,
        "reader":{
            // Existing file required by validation; this test never spawns it.
            "program":std::env::current_exe().expect("test executable"),
            "args":[],
            "model_profile":{
                "id":"deterministic-owned-subprocess","family":"deterministic-fixture",
                "tokenizer_id":"contextdb.reference_unicode_tokens.v1","renderer":"compact",
                "max_context_tokens":8192,"reserved_output_tokens":512,
                "preferred_structured_format":"compact_text","supports_tool_results":false,
                "supports_native_citations":false,"supports_prompt_caching":false,
                "position_profile":"critical_first","instruction_hierarchy":"separated_channels",
                "max_schema_complexity":64,"external_processing":false
            }
        }
    });
    if let Some(profile) = profile {
        value["router_trace_profile"] = serde_json::to_value(profile).expect("profile");
    }
    let config: HostConfig = serde_json::from_value(value).expect("actual parsed host config");
    config.validate().expect("bounded host configuration");
    config
}

// Frozen v1 shapes are intentional: accepted Off runs must keep exactly their
// original bytes, including field order and parsed reader defaults.
#[derive(Serialize)]
struct LegacyConfig<'a> {
    schema_version: u16,
    identity: &'a HostIdentity,
    control: &'a str,
    input_tokens: u32,
    reader: &'a LocalReaderConfig,
}

#[derive(Serialize)]
struct LegacySettings<'a> {
    profile: &'static str,
    control: &'a [OutgoingMessage],
    purpose: PackPurpose,
    memory_budget: &'a ContextBudgets,
    outgoing_budget: &'a OutgoingBudget,
    rolling: (u32, u32, usize, usize, u8),
    automatic_recall_filter: &'a RawFilter,
    cache_residency: &'static str,
    tools: &'static str,
    preparation: &'static str,
    raw_projection_limits: (u32, u8),
}

fn legacy_config(config: &HostConfig) -> LegacyConfig<'_> {
    LegacyConfig {
        schema_version: config.schema_version,
        identity: &config.identity,
        control: &config.control,
        input_tokens: config.input_tokens,
        reader: &config.reader,
    }
}

fn legacy_binding(config: &HostConfig) -> Vec<u8> {
    let settings = config.settings().expect("existing host settings");
    let binding = LegacySettings {
        profile: "contextdb.cli-owned-host-settings.v1",
        control: &settings.control,
        purpose: settings.purpose,
        memory_budget: &settings.memory_budget,
        outgoing_budget: &settings.outgoing_budget,
        rolling: (
            settings.rolling.high_tokens,
            settings.rolling.low_tokens,
            settings.rolling.keep_complete_groups,
            settings.rolling.chunk_groups,
            settings.rolling.max_prepare_attempts,
        ),
        automatic_recall_filter: &settings.automatic_recall_filter,
        cache_residency: "disabled",
        tools: "no-external-tools",
        preparation: preparation::PROFILE,
        raw_projection_limits: (preparation::BATCH_EVENTS, preparation::MAX_BATCHES),
    };
    serde_json::to_vec(&(legacy_config(config), binding)).expect("frozen legacy binding bytes")
}

#[test]
fn omitted_and_explicit_off_preserve_exact_legacy_configuration_and_digest() {
    let omitted = config(None);
    let explicit = config(Some(RouterTraceProfile::Off));
    let old_config = serde_json::to_vec(&legacy_config(&omitted)).expect("legacy config");
    assert_eq!(
        serde_json::to_vec(&omitted).expect("current config"),
        old_config
    );
    assert_eq!(
        serde_json::to_vec(&explicit).expect("explicit Off config"),
        old_config
    );
    let old_binding = legacy_binding(&omitted);
    assert_eq!(omitted.binding_bytes().expect("bound bytes"), old_binding);
    assert_eq!(
        explicit.binding_bytes().expect("explicit Off bound bytes"),
        old_binding
    );
    assert_eq!(
        omitted.digest().expect("digest"),
        blake3::hash(&old_binding).to_hex().to_string()
    );
    assert_eq!(
        explicit.digest().expect("explicit digest"),
        omitted.digest().expect("default digest")
    );
    assert_eq!(
        omitted.settings().expect("settings").router_trace_profile,
        RouterTraceProfile::Off
    );
    let mut null = serde_json::to_value(&omitted).expect("legacy config value");
    null["automatic_hybrid"] = Value::Null;
    let null: HostConfig = serde_json::from_value(null).expect("explicit absent hybrid");
    assert_eq!(null.binding_bytes().expect("absent binding"), old_binding);
    assert!(null.automatic_hybrid.is_none());
}

fn hybrid_config() -> HostConfig {
    let mut config = config(Some(RouterTraceProfile::RequiredReplayV2));
    let root = std::env::current_exe()
        .expect("test executable")
        .parent()
        .expect("absolute fixture parent")
        .join("not-provisioned-config-only-encoder");
    config.automatic_hybrid = Some(HybridConfig {
        encoder: LocalEmbeddingConfig {
            program: root.join("llama-server"),
            model: root.join("Qwen3-Embedding-0.6B-Q8_0.gguf"),
            runtime_artifacts: std::collections::BTreeMap::from([(
                "llama-server".into(),
                "1".repeat(64),
            )]),
            port: 29781,
        },
        limits: OwnedHybridLimits::default(),
    });
    config.validate().expect("pure bounded hybrid declaration");
    config
}

#[test]
fn routed_binding_is_distinct_and_absent_routing_keeps_hybrid_bytes() {
    let legacy = hybrid_config();
    let legacy_bytes = legacy.binding_bytes().expect("existing hybrid binding");
    let mut absent = serde_json::to_value(&legacy).expect("old hybrid config");
    absent["automatic_hybrid"]["limits"]["routed"] = Value::Null;
    let absent: HostConfig = serde_json::from_value(absent).expect("explicit absent route");
    absent.validate().expect("existing hybrid remains valid");
    assert_eq!(
        absent.binding_bytes().expect("old canonical bytes"),
        legacy_bytes
    );
    let mut value = serde_json::to_value(&legacy).expect("original hybrid config");
    value["automatic_hybrid"]["limits"]["routed"] = json!({
        "max_fine_paths":8,"coarse_node_reads":64,"coarse_vector_reads":64,
        "coarse_discovered":64,"coarse_ef_search":32
    });
    let routed: HostConfig = serde_json::from_value(value.clone()).expect("parsed routed config");
    routed
        .validate()
        .expect("explicit routed profile with replay v2");
    let bound: Value = serde_json::from_slice(&routed.binding_bytes().expect("routed binding"))
        .expect("canonical routed JSON");
    assert_eq!(
        bound[1]["automatic_hybrid"]["profile"],
        "contextdb.cli-owned-routed-hybrid-settings.v2"
    );
    assert_eq!(
        bound[1]["automatic_hybrid"]["preparation"],
        preparation::ROUTED_PROFILE
    );
    assert_eq!(
        bound[1]["automatic_hybrid"]["projection_limits"],
        json!([4, 8])
    );
    assert_eq!(
        bound[1]["automatic_hybrid"]["maintenance"],
        json!({
            "max_work": 250_000_000_u64, "max_bytes": 8_u64 * 1024 * 1024 * 1024,
            "timeout_millis": 180_000_u64,
        })
    );
    assert_ne!(
        routed.digest().expect("routed digest"),
        legacy.digest().expect("old hybrid digest")
    );
    assert!(
        routed
            .settings()
            .expect("inert parsed settings")
            .automatic_hybrid
            .is_none()
    );
    value["automatic_hybrid"]["limits"]["segments"] = json!({"max_segments":1});
    let conflicting: HostConfig =
        serde_json::from_value(value).expect("parsed conflicting profile");
    assert!(
        conflicting.validate().is_err(),
        "the CLI does not activate old segmented queries"
    );
}

#[test]
fn hybrid_binds_full_pinned_profile_without_starting_or_reading_encoder_assets() {
    let host = hybrid_config();
    let hybrid = host.automatic_hybrid.as_ref().expect("explicit hybrid");
    let profile = hybrid.embedding_profile().expect("fixed pure profile");
    let bound: Value = serde_json::from_slice(&host.binding_bytes().expect("hybrid binding"))
        .expect("parsed canonical binding");
    let settings = &bound[1]["automatic_hybrid"];
    assert_eq!(bound[0]["automatic_hybrid"]["encoder"], settings["encoder"]);
    assert_eq!(settings["embedding_profile"], json!(profile));
    assert_eq!(
        settings["embedding_profile_digest"],
        json!(profile.digest().expect("complete profile digest"))
    );
    assert_eq!(settings["limits"], json!(OwnedHybridLimits::default()));
    assert_eq!(settings["preparation"], preparation::HYBRID_PROFILE);
    assert_eq!(
        settings["projection_limits"],
        json!([
            preparation::HYBRID_BATCH_EVENTS,
            preparation::HYBRID_MAX_BATCHES
        ])
    );
    assert_eq!(
        settings["startup"],
        json!({
            "max_work":super::super::HYBRID_STARTUP_MAX_WORK,
            "max_bytes":super::super::HYBRID_STARTUP_MAX_BYTES,
            "timeout_millis":super::super::HYBRID_STARTUP_TIME_MS
        })
    );
    assert_eq!(
        settings["shutdown"],
        json!({
            "max_work":super::super::HYBRID_SHUTDOWN_MAX_WORK,
            "max_bytes":super::super::HYBRID_SHUTDOWN_MAX_BYTES,
            "timeout_millis":super::super::HYBRID_SHUTDOWN_TIME_MS
        })
    );
    assert_ne!(
        host.digest().expect("hybrid digest"),
        config(Some(RouterTraceProfile::RequiredReplayV2))
            .digest()
            .expect("legacy v2 digest")
    );
    let inert = host.settings().expect("pure host settings");
    assert!(inert.automatic_hybrid.is_none());
    assert!(inert.automatic_bm25.is_none());
}

#[test]
fn hybrid_refuses_wrong_profile_invalid_limits_paths_ports_and_unknown_fields() {
    let config = hybrid_config();
    let value = serde_json::to_value(&config).expect("hybrid config value");
    for profile in [RouterTraceProfile::Off, RouterTraceProfile::Required] {
        let mut changed = value.clone();
        changed["router_trace_profile"] = json!(profile);
        let changed: HostConfig = serde_json::from_value(changed).expect("parsed other trace");
        assert!(changed.validate().is_err());
    }
    for (field, changed_value) in [
        ("program", json!("relative-server")),
        ("model", json!("relative-model.gguf")),
        ("port", json!(0)),
        ("runtime_artifacts", json!({})),
        ("runtime_artifacts", json!({"llama-server":"invalid-sha"})),
    ] {
        let mut changed = value.clone();
        changed["automatic_hybrid"]["encoder"][field] = changed_value;
        let changed: HostConfig = serde_json::from_value(changed).expect("parsed invalid encoder");
        assert!(changed.validate().is_err(), "invalid encoder field {field}");
    }
    let mut changed = value.clone();
    changed["automatic_hybrid"]["limits"]["sources"] = json!(19);
    let changed: HostConfig = serde_json::from_value(changed).expect("parsed invalid limits");
    assert!(changed.validate().is_err());
    for path in [
        vec!["automatic_hybrid", "embedding_profile"],
        vec!["automatic_hybrid", "encoder", "allow_remote"],
        vec!["automatic_hybrid", "limits", "unbounded"],
    ] {
        let mut changed = value.clone();
        let mut parent = &mut changed;
        for key in &path[..path.len() - 1] {
            parent = &mut parent[*key];
        }
        parent[path[path.len() - 1]] = json!(true);
        assert!(serde_json::from_value::<HostConfig>(changed).is_err());
    }
    let worker_directory = tempfile::tempdir().expect("owned worker pins");
    let worker_root =
        std::fs::canonicalize(worker_directory.path()).expect("canonical worker pins");
    let program = worker_root.join("interpreter");
    std::fs::write(&program, b"never executed").expect("owned dummy interpreter");
    let mut combined = hybrid_config();
    combined.development_kev = Some(crate::owned_conversation::kev::tests::fixture_config(
        &worker_root,
        program,
    ));
    assert!(
        combined.validate().is_err(),
        "development scorer remains a separate opt-in"
    );
}

fn changed_hybrid_configs(original: &HostConfig) -> Vec<HostConfig> {
    let value = serde_json::to_value(original).expect("accepted hybrid value");
    let mut changed = Vec::new();
    let mut port = value.clone();
    port["automatic_hybrid"]["encoder"]["port"] = json!(29782);
    changed.push(port);
    let mut limits = value.clone();
    limits["automatic_hybrid"]["limits"]["sources"] = json!(65);
    changed.push(limits);
    let mut pins = value.clone();
    pins["automatic_hybrid"]["encoder"]["runtime_artifacts"]["llama-server"] =
        json!("2".repeat(64));
    changed.push(pins);
    let mut model = value.clone();
    model["automatic_hybrid"]["encoder"]["model"] = json!(
        original
            .automatic_hybrid
            .as_ref()
            .expect("hybrid")
            .encoder
            .model
            .with_file_name("changed-location.gguf")
    );
    changed.push(model);
    let mut identity = value;
    identity["identity"]["actor_id"] = json!("10000000-0000-4000-8000-000000000008");
    changed.push(identity);
    changed
        .into_iter()
        .map(|value| {
            let config: HostConfig = serde_json::from_value(value).expect("changed parsed config");
            config.validate().expect("changed valid declaration");
            config
        })
        .collect()
}

#[test]
fn hybrid_changes_bind_identity_port_limits_paths_and_full_backend_profile() {
    let original = hybrid_config();
    let digest = original.digest().expect("original digest");
    let profile_digest = original
        .automatic_hybrid
        .as_ref()
        .expect("hybrid")
        .embedding_profile()
        .expect("profile")
        .digest()
        .expect("profile digest");
    for (index, changed) in changed_hybrid_configs(&original).into_iter().enumerate() {
        assert_ne!(changed.digest().expect("changed digest"), digest);
        let changed_profile = changed
            .automatic_hybrid
            .as_ref()
            .expect("hybrid")
            .embedding_profile()
            .expect("profile")
            .digest()
            .expect("profile digest");
        if index == 2 {
            assert_ne!(
                changed_profile, profile_digest,
                "complete runtime pins change the encoder space"
            );
        } else {
            assert_eq!(
                changed_profile, profile_digest,
                "host settings do not manufacture another encoder"
            );
        }
    }
}

#[test]
fn accepted_hybrid_binding_survives_cold_open_and_refuses_changed_resume_hash() {
    let directory = tempfile::tempdir().expect("native fixture directory");
    let authorities = tempfile::tempdir().expect("retained authorities");
    let ledger =
        NativeSuppressionLedger::create(authorities.path().join("ledger"), "hybrid-config")
            .expect("retained suppression authority");
    let keys = NativeCustodyKeys::create(
        authorities.path().join("keys"),
        "hybrid-config",
        CustodyMasterKey::from_zeroizing(zeroize::Zeroizing::new([9; 32])).expect("fixture master"),
    )
    .expect("retained custody authority");
    let owner = Arc::new(
        NativeService::open_encrypted(
            directory.path(),
            "hybrid-config",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("actual encrypted native owner"),
    );
    let original = hybrid_config();
    let identity = original.identity();
    let digest = original.digest().expect("hybrid digest");
    let key = TokenKey::new([11; 32]).expect("host authority key");
    let context = authority(&key, &identity, &digest).expect("actual host principal");
    let accepted = binding::require_binding(&owner, &context, &identity, &digest, true)
        .expect("accepted hybrid binding without encoder launch");
    drop(owner);
    let reopened = Arc::new(
        NativeService::open_encrypted_existing(
            directory.path(),
            "hybrid-config",
            [7; 32],
            ledger,
            keys,
        )
        .expect("cold native owner"),
    );
    assert_eq!(
        binding::require_binding(&reopened, &context, &identity, &digest, false)
            .expect("same cold hybrid binding")
            .receipt,
        accepted.receipt
    );
    for changed in changed_hybrid_configs(&original).into_iter().take(4) {
        let changed_digest = changed.digest().expect("changed digest");
        let changed_context =
            authority(&key, &identity, &changed_digest).expect("new trusted binding");
        let error = binding::require_binding(
            &reopened,
            &changed_context,
            &identity,
            &changed_digest,
            false,
        )
        .err()
        .expect("changed hybrid declaration cannot resume the accepted run");
        assert_eq!(error.0.code, contextdb_service::ErrorCode::InvalidArgument);
    }
    assert_eq!(
        binding::require_binding(&reopened, &context, &identity, &digest, false)
            .expect("failed switches did not replace accepted binding")
            .receipt,
        accepted.receipt
    );
}

#[test]
fn required_binds_the_fixed_profile_and_rejects_unknown_or_overridden_limits() {
    let off = config(None);
    let required = config(Some(RouterTraceProfile::Required));
    assert_ne!(
        required.digest().expect("Required digest"),
        off.digest().expect("Off digest")
    );
    assert_eq!(
        required.settings().expect("settings").router_trace_profile,
        RouterTraceProfile::Required
    );
    let bound: Value = serde_json::from_slice(&required.binding_bytes().expect("binding bytes"))
        .expect("protected settings binding");
    assert_eq!(bound[0]["router_trace_profile"], "required");
    assert_eq!(
        bound[1]["router_trace"],
        json!({
            "profile":"required","version":1,"max_trace_bytes":2*1024*1024,"max_pages":8,
            "max_page_bytes":256*1024,"max_native_row_bytes":8*1024*1024,
            "max_inline_novel_bytes":256*1024
        })
    );
    let mut unknown = serde_json::to_value(&required).expect("config value");
    unknown["router_trace_profile"] = json!("unknown-profile");
    assert!(serde_json::from_value::<HostConfig>(unknown).is_err());
    let mut overridden = serde_json::to_value(&required).expect("config value");
    overridden["router_trace_limits"] = json!({"max_trace_bytes":32*1024*1024});
    assert!(serde_json::from_value::<HostConfig>(overridden).is_err());
}

#[test]
fn replay_v2_binds_its_own_profile_without_changing_required_v1() {
    let required = config(Some(RouterTraceProfile::Required));
    let replay = config(Some(RouterTraceProfile::RequiredReplayV2));
    assert_ne!(
        replay.digest().expect("v2 digest"),
        required.digest().expect("v1 digest")
    );
    let bound: Value = serde_json::from_slice(&replay.binding_bytes().expect("v2 binding"))
        .expect("parsed v2 binding");
    assert_eq!(bound[0]["router_trace_profile"], "required_replay_v2");
    assert_eq!(
        bound[1]["router_trace"],
        json!({
            "profile":"required_replay_v2","version":2,"max_trace_bytes":2*1024*1024,
            "max_pages":8,"max_page_bytes":256*1024,"max_native_row_bytes":8*1024*1024,
            "max_inline_novel_bytes":256*1024
        })
    );
}

#[test]
fn accepted_config_binding_survives_cold_open_and_refuses_a_trace_profile_switch() {
    for profile in [
        RouterTraceProfile::Off,
        RouterTraceProfile::Required,
        RouterTraceProfile::RequiredReplayV2,
    ] {
        cold_configuration_profile_refusal(profile);
    }
}

fn cold_configuration_profile_refusal(profile: RouterTraceProfile) {
    let directory = tempfile::tempdir().expect("native fixture directory");
    let authority_directory = tempfile::tempdir().expect("retained authorities");
    let ledger =
        NativeSuppressionLedger::create(authority_directory.path().join("ledger"), "host-config")
            .expect("retained suppression authority");
    let keys = NativeCustodyKeys::create(
        authority_directory.path().join("keys"),
        "host-config",
        CustodyMasterKey::from_zeroizing(zeroize::Zeroizing::new([9; 32])).expect("fixture master"),
    )
    .expect("retained custody authority");
    let owner = Arc::new(
        NativeService::open_encrypted(
            directory.path(),
            "host-config",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("actual encrypted native owner"),
    );
    let original = config(Some(profile));
    let identity = original.identity();
    let original_digest = original.digest().expect("accepted profile digest");
    let key = TokenKey::new([11; 32]).expect("host authority key");
    let context = authority(&key, &identity, &original_digest).expect("actual host principal");
    let accepted = binding::require_binding(&owner, &context, &identity, &original_digest, true)
        .expect("accepted original config binding");
    drop(owner);
    let reopened = Arc::new(
        NativeService::open_encrypted_existing(
            directory.path(),
            "host-config",
            [7; 32],
            ledger,
            keys,
        )
        .expect("cold native owner"),
    );
    let cold = binding::require_binding(&reopened, &context, &identity, &original_digest, false)
        .expect("same retained configuration");
    assert_eq!(cold.receipt, accepted.receipt);
    for other in [
        RouterTraceProfile::Off,
        RouterTraceProfile::Required,
        RouterTraceProfile::RequiredReplayV2,
    ] {
        if other == profile {
            continue;
        }
        let changed = config(Some(other));
        let new_digest = changed.digest().expect("changed profile digest");
        let changed_context =
            authority(&key, &identity, &new_digest).expect("new authenticated config");
        let error =
            binding::require_binding(&reopened, &changed_context, &identity, &new_digest, false)
                .err()
                .expect("profile change refused by actual retained binding");
        assert_eq!(error.0.code, contextdb_service::ErrorCode::InvalidArgument);
    }
    assert_eq!(
        binding::require_binding(&reopened, &context, &identity, &original_digest, false)
            .expect("failed switch did not replace accepted configuration")
            .receipt,
        accepted.receipt
    );
    // The actual retained binding refuses a learned opt-in before any worker
    // constructor, launch or private semantic callback is reached.
    let worker_directory = tempfile::tempdir().expect("owned worker pins");
    let worker_root =
        std::fs::canonicalize(worker_directory.path()).expect("canonical worker pins");
    let program = worker_root.join("interpreter");
    std::fs::write(&program, b"never executed").expect("owned dummy interpreter");
    let worker = crate::owned_conversation::kev::tests::fixture_config(&worker_root, program);
    let mut changed = config(Some(profile));
    changed.development_kev = Some(worker);
    if profile.is_off() {
        assert!(
            changed.validate().is_err(),
            "Off has no processed-frontier custody"
        );
    } else {
        changed
            .validate()
            .expect("explicit bounded development config");
        let digest = changed.digest().expect("worker code/weights/policy bound");
        assert_ne!(digest, original_digest);
        let changed_context = authority(&key, &identity, &digest).expect("new trusted binding");
        let error =
            binding::require_binding(&reopened, &changed_context, &identity, &digest, false)
                .err()
                .expect("worker opt-in cannot replace a cold accepted binding");
        assert_eq!(error.0.code, contextdb_service::ErrorCode::InvalidArgument);
    }
}
