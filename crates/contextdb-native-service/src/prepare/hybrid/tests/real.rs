//! Explicit host-only proof; no synthetic vector enters the real branch.

use super::*;
use std::{io::Read, time::Duration};

#[test]
#[ignore = "requires explicitly provisioned pinned local GPU encoder assets"]
fn real_encoder_uses_same_encrypted_owned_hybrid_tool_and_cold_recovery_flow() {
    let path = std::env::var_os("CONTEXTDB_DENSE_ENCODER_CONFIG")
        .expect("explicit pinned host embedding config");
    let mut config_bytes = Vec::new();
    std::fs::File::open(path)
        .expect("provisioned encoder config")
        .take(64 * 1024 + 1)
        .read_to_end(&mut config_bytes)
        .expect("bounded encoder config read");
    assert!(config_bytes.len() <= 64 * 1024, "host config size bound");
    let config: LocalEmbeddingConfig =
        serde_json::from_slice(&config_bytes).expect("trusted pinned encoder config");
    // Asset hashing and process startup are paid once outside the query parent.
    let mut provisioning = QueryBudget::new(
        1_000_000,
        4 * 1024 * 1024 * 1024,
        Duration::from_secs(120),
        Default::default(),
    );
    let backend = OwnedLocalEmbedding::launch(&config, &mut provisioning)
        .expect("verified real offline owned encoder");
    let encoder = Arc::new(Encoder::real(backend));
    let encoder = run_vertical(fixture_with_encoder(encoder));
    let mut encoder = Arc::try_unwrap(encoder)
        .expect("all runtime, hook and resumed encoder references released");
    let mut cleanup = QueryBudget::new(
        100_000,
        1024 * 1024,
        Duration::from_secs(10),
        Default::default(),
    );
    encoder
        .shutdown(&mut cleanup)
        .expect("owned backend shutdown");
}
