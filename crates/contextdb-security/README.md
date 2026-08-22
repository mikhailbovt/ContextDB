# ContextDB security kernel

`contextdb-security` owns the deterministic M16 security primitives that must
remain independent from storage engines, network transports, and model
providers. Hosts provide durable sinks, authorization decisions, and keys;
this crate validates the security contracts and produces verifiable receipts.

## M16 acceptance matrix

| Requirement | Implementation and executable evidence |
| --- | --- |
| encrypted backup and isolated restore | XChaCha20-Poly1305 archive with canonical authenticated header; Ed25519-signed content-free manifest; explicit database, workspace, scope, policy, key, expiry, and rotation bindings; authorization is checked before decryption |
| hard-delete lineage | immediate live suppression plus a monotonic workflow covering primary data, semantic projections, summaries, embeddings, ANN, lexical indexes, caches, checkpoints, providers, exports, and backups; completion emits a signed receipt |
| consent and old snapshots | database/workspace-bound `LivePolicyOverlay` validates serialized state during decode and requires an externally retained signed exact-head checkpoint (including signing-key identity and generation) before lookup/restore; current denial applies to retained snapshots and pre-delete restored backups; hard-delete denial cannot be released |
| tenant/resource isolation | workspace-partitioned, idempotent admission leases with monotonic expiry, bounded restart decoding, and concurrency, byte, candidate, frontier, hop, retry, and snapshot-TTL limits |
| prompt injection and poisoning | source taint classification, bounded sanitization, no instruction or tool authority from retrieved text, and explicit sensitive-inference authorization |
| secret handling | bounded scanner and fail-closed policy for reject, redact, XChaCha20-Poly1305 encrypted restricted fields, keyed digest-only, source handle, or strict opaque vault reference; exact database/workspace/record/field/scope/policy metadata and key rotation generation are authenticated; public offline plaintext verifiers are forbidden |
| audit integrity | content-free append-only BLAKE3 chain signed with Ed25519 plus independently retained signed-head checkpoints that detect suffix truncation |
| BENCH-G | `examples/bench_g.rs` executes all nine normative absent-vs-denied-content comparisons; candidates, ranking, summaries, evidence, no-touch counters, and coarse timing are invariant |
| supply chain | pinned `Cargo.lock`, RustSec audit, `cargo-deny` license/source/duplicate policy, an exact local-MCP CycloneDX 1.5 SBOM, and fresh artifact-bound SBOM generation in release-candidate CI |
| unsafe Rust | workspace `unsafe_code = "forbid"`; source audit contains no Rust unsafe block |

## Verification

```powershell
cargo fmt -p contextdb-security -- --check
cargo test -p contextdb-security --no-fail-fast
cargo clippy -p contextdb-security --all-targets -- -D warnings
$env:RUSTDOCFLAGS = '-D warnings'; cargo doc -p contextdb-security --no-deps
cargo run -p contextdb-security --example bench_g --quiet
cargo audit --deny warnings
cargo deny check
```

Canonical proof artifacts live in `proof/M16`. The crate-level tests prove the
security kernel; the M16 release gate additionally requires the repository-wide
fault matrix and a completed deep security scan.

## Deliberate boundaries

- Encryption and signing keys are supplied by an OS keyring, KMS, HSM, or host
  adapter. ContextDB never persists plaintext key material in its data path.
- Restricted-field keys and backup-encryption keys are distinct Rust types and
  key-management roles. Rewrap requires a distinct, strictly newer field-key
  generation; authorized decryption returns zeroizing plaintext.
- Live-policy checkpoints without a signing-key generation are rejected. This
  intentional wire-format break prevents a checkpoint signed under retired
  generation metadata from being promoted to the current authorization head.
- TLS/mTLS termination and network identity are server-deployment concerns.
- A deletion adapter must implement `DeletionEvidenceVerifier`; the kernel will
  not sign completion until the adapter proves exact authoritative closure and
  every target attestation. It never fabricates provider, export, or backup erasure.
- CycloneDX files describe build inputs. Release artifact provenance and an
  external signing identity are M18/M19 responsibilities.
- BENCH-G is the deterministic policy-first oracle. The final M16 report also
  includes cross-crate isolation tests and the independent deep scan.
