# Upgrade and migration

Risky v1 transformations are side-by-side, never blind in-place rewrites.

## Preflight

1. Capture old/new version manifests and artifact SHA-256 values.
2. Verify the running database and create a logical plus policy-required
   encrypted backup.
3. Check writer, `read_min`, `read_max`, required feature flags, migration ID,
   free-space requirement, checksum plan and rollback policy.
4. Stop if the new reader does not accept the old format or an enabled durable
   feature is unknown.
5. Keep the old binary, database path, key material and verification receipt
   unchanged until postflight passes.

Both binaries receive the intended key through exactly one external environment
source. Each database path also receives its own external state-head authority:
the existing authority remains bound to `old.ctxb`, while `candidate.ctxb` gets
a fresh empty authority. On Windows those are distinct
`CONTEXTDB_STATE_HEAD_ID` values in HKCU; on Unix they are distinct absolute,
owner-protected `CONTEXTDB_STATE_HEAD_FILE` paths outside both archive
directories. The logical archive carries neither key nor authority, and
migration must not silently generate, rotate, copy, or co-locate either.

## Side-by-side workflow

```text
old-contextdb --json doctor old.ctxb
old-contextdb --json export old.ctxb migration-input.ctxb
new-contextdb --json import candidate.ctxb migration-input.ctxb
new-contextdb --json doctor candidate.ctxb
```

Run semantic/conformance and application probes against `candidate.ctxb`, then
switch the configured path atomically at the supervisor/deployment boundary.
Rollback switches both configuration values back to the untouched old path and
its matching old authority; do not ask the old binary to open a format it did
not declare readable. Never restore an old archive together with a rolled-back
authority snapshot and call that anti-rollback proof.

`init --force` and `import --force` are disabled. A candidate path or authority
that already exists is an operator error, not permission to overwrite it.

## Runtime preflight foundation

`contextdb-format::FormatRegistry` is the machine-enforced preflight boundary for
durable format families. It records inclusive reader ranges, supported required
features, unique directional migration edges, rollback policy, checksum-plan
identifiers and conservative free-space formulae. Registry planning is
deterministic and side-effect free: an unknown required feature, missing path or
insufficient space stops before any payload or target generation is touched.

The registry is deliberately not a migration executor. A host must still seal
a checkpoint, execute each registered descriptor, verify its declared checksum
plan and atomically activate the verified target while leaving the source and
its authority untouched until postflight succeeds.

The production service exposes one exact, side-effect-free identity preflight:
`migrate-format` with target
`contextdb.production-fjall.state-root-v2.runtime-ledger-v1`. It authenticates
the host request, deep-verifies Fjall, runtime ledger, durable history and the
external authority, then returns current status without creating a successor.
Any other target fails with `format_incompatible` and the current-format marker
before mutation. This makes current-format automation explicit; it does not
pretend that a registered rewrite executor exists.

## Remaining gap

The version and release contracts can record compatibility and migration
evidence, and logical export/import provides a fallback. The release tooling
also includes a non-publishing operational drill which exercises this
side-by-side sequence, an explicit switch back to the untouched old database,
and a disaster-recovery clone in disposable directories. That drill produces
candidate evidence only; it is not a production supervisor or a release
decision.

An online/background migration coordinator, production rollback automation,
historical cross-version fixture matrix and supported-version policy are not
yet complete. `M18-E02`, `M18-E03`, and RFC 31 migration gates remain open until
the executors and exact-version receipts from supported platforms exist.
