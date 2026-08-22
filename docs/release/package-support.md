# Package and platform support

The machine-readable source of truth is `release/package-matrix.json`.
`platforms` lists artifact targets; `runtime_platforms` lists clean-install
receipt targets. A platform-independent archive can therefore remain one
artifact while still requiring Linux, macOS, and visible best-effort Windows
runtime receipts.

## Platform tiers

| Platform | Tier | Required native evidence |
|---|---|---|
| Linux x86_64 | required | build/package, clean install, operations, upgrade/rollback, artifact and publication digests |
| Linux arm64 | required | same |
| macOS arm64 | required | same |
| Windows x86_64 | best effort | same probes; failures reported rather than hidden |

The OCI image targets Linux x86_64 and Linux arm64. Platform-independent source,
SDK, docs, dataset, checksum and example packages still need isolated consumer
probes where the matrix marks `runtime_required`.

## Package state vocabulary

- `source-present`: a source path exists; no package or runtime claim.
- `packaging-ready-static`: package recipe/fixture exists and was checked without
  the target runtime.
- `package-built`: immutable package assembled and hashed, not necessarily run.
- `runtime-proven`: exact digest has a passing target receipt.
- `external-proof-required`: registry/public/human evidence cannot be generated
  locally.
- `not-implemented`: required product surface is absent.

Current source audit intentionally leaves all 17 release package requirements
unsatisfied. In particular, the intended public Rust crate subset is not frozen,
and five workspace packages explicitly set `publish = false`; a crates.io
release cannot be inferred from a successful workspace build.

`release/documentation-matrix.json` inventories fourteen public documentation categories.
At this snapshot ten categories are source-complete and four remain partial:
operations, benchmarks, migration, and packaged examples. The API category is
source-complete because the canonical compatibility policy, protocol, route and
SDK contracts are present and cross-checked; it is not runtime- or
publication-verified. No category is yet runtime- or publication-verified. This
prevents the existence of a `docs` directory—or a newly written guide—from
being mistaken for the full-docs release artifact gate.

## Clean-install probe contract

The standalone verifier copies a complete bundle to a fresh temporary directory
before verification. For the host `contextdb` binary it runs:

```text
inject an ephemeral CONTEXTDB_TOKEN_KEY_HEX into the child process only
Windows: select a unique CONTEXTDB_STATE_HEAD_ID for each destination (HKCU)
Unix: select an owner-only CONTEXTDB_STATE_HEAD_FILE outside the bundle/data directory
contextdb version
assert the first output line is `contextdb <manifest release version>`
contextdb --json init <fresh>/state.ctxb
assert no token-key or state-head sidecar exists under <fresh>
contextdb --json doctor <fresh>/state.ctxb
contextdb --json export <fresh>/state.ctxb <fresh>/exported.ctxb
select a second fresh state-head authority for the clone destination
contextdb --json import <fresh>/imported.ctxb <example.ctxb>
assert import had no --force and no token-key/state-head sidecar exists under <fresh>
contextdb --json doctor <fresh>/imported.ctxb
```

On Windows the probe never supplies `CONTEXTDB_TOKEN_KEY_FILE` or
`CONTEXTDB_STATE_HEAD_FILE`; on Unix it never supplies
`CONTEXTDB_STATE_HEAD_ID`. The secret, authority selector/path, and authority
contents are not emitted into the receipt, and the receipt hashes stdout/stderr
instead of copying potentially sensitive payloads. Import and init are
clone/create-only and never exercise `--force`. Additional language-package
jobs must create a clean virtual environment/module/project, install only the
built artifact plus declared dependencies, import/compile it, and run the
published example. A repository working tree with cached `target`, `.venv`, or
`node_modules` is not clean-install evidence.

## Upgrade, rollback, and disaster-recovery drill

`operational-drill` consumes two already assembled bundles and a schema-valid,
digest-pinned plan. The new SemVer precedence must be strictly greater, and the
plan must bind a non-empty portable seed artifact plus its minimum commit
sequence. It refuses a host/plan target
mismatch, overlapping bundle roots, invalid bundle verification, artifact
digest drift, or anything other than the complete upgrade/rollback/DR scenario
set. Old, candidate and recovered databases receive distinct external
state-head authorities while retaining one ephemeral token key for logical
continuity. The old logical export must remain byte-identical after candidate
activation and explicit rollback.

The runner records content-free canonical logical-export digests, exact
non-secret argv, hashed command output, the isolated activation sequence and
authority cleanup. It invokes no network command, but does not claim OS-level
network isolation. It never passes `--force`, invokes Docker or changes a real
supervisor.
Required Linux x86_64, Linux arm64 and macOS arm64 receipts, plus visible
best-effort Windows evidence, still must be produced by those native runners and
intaken before final bundle assembly.

Docker build/run is explicitly outside the current local proof. Static source
is under `deploy/docker`; the Dockerfile-specific ignore list prevents local
targets, keys and caches from entering the build context. Compose declares
distinct archive and state-head volumes, but only a live target-runtime receipt
can prove ownership, restart persistence, and non-rollback custody.
