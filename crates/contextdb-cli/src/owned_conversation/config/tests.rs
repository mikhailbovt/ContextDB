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
fn accepted_config_binding_survives_cold_open_and_refuses_a_trace_profile_switch() {
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
    let off = config(None);
    let identity = off.identity();
    let off_digest = off.digest().expect("Off digest");
    let key = TokenKey::new([11; 32]).expect("host authority key");
    let context = authority(&key, &identity, &off_digest).expect("actual host principal");
    let accepted = binding::require_binding(&owner, &context, &identity, &off_digest, true)
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
    let cold = binding::require_binding(&reopened, &context, &identity, &off_digest, false)
        .expect("same retained configuration");
    assert_eq!(cold.receipt, accepted.receipt);
    let required = config(Some(RouterTraceProfile::Required));
    let new_digest = required.digest().expect("Required digest");
    let changed_context =
        authority(&key, &identity, &new_digest).expect("new authenticated config");
    let error =
        binding::require_binding(&reopened, &changed_context, &identity, &new_digest, false)
            .err()
            .expect("profile change refused by actual retained binding");
    assert_eq!(error.0.code, contextdb_service::ErrorCode::InvalidArgument);
    assert_eq!(
        binding::require_binding(&reopened, &context, &identity, &off_digest, false)
            .expect("failed switch did not replace accepted configuration")
            .receipt,
        accepted.receipt
    );
}
