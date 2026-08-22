# Local run, status, and verification

The current one-binary path is `contextdb`. This documents commands that exist
now; it does not declare operational M18/M19 gates passed.

```text
# Windows (inject the key from an OS secret store into the child only):
set CONTEXTDB_TOKEN_KEY_HEX=<64 hex characters>
set CONTEXTDB_STATE_HEAD_ID=contextdb-local

# Unix alternative:
export CONTEXTDB_TOKEN_KEY_FILE=/protected/contextdb/token-key.hex
export CONTEXTDB_STATE_HEAD_FILE=/protected/contextdb/state-head.json

contextdb version
contextdb --json init ./state/contextdb.ctxb
contextdb --json status ./state/contextdb.ctxb
contextdb --json doctor ./state/contextdb.ctxb
contextdb serve ./state/contextdb.ctxb \
  --http-listen 127.0.0.1:7733 \
  --grpc-listen 127.0.0.1:7734
```

`doctor` performs deep logical export/import replay and returns `valid`,
`commit_seq`, and the logical archive BLAKE3 digest. `status` is a shallow
logical verification. Neither command substitutes for M16 deep physical
corruption, encrypted-backup, deletion-lineage, dependency, or security checks.

The release contract requires exactly one external token-key source:
`CONTEXTDB_TOKEN_KEY_HEX` or `CONTEXTDB_TOKEN_KEY_FILE`. A key file must be
an absolute regular path outside the archive directory. Its content is exactly
64 hexadecimal characters plus an optional single LF/CRLF; an all-zero key is
rejected. On Unix, it must be owner-only, have one hard link, and be read through
a bounded no-follow handle. File-backed token keys are intentionally disabled on
Windows; inject `CONTEXTDB_TOKEN_KEY_HEX` from DPAPI, a credential broker, or
another OS secret-store adapter into the child process only. Creating an
adjacent plaintext `<archive>.key` is forbidden.

Every persistent database also requires an independent authenticated state-head
authority. Windows uses an HKCU namespace selected by the explicit
`CONTEXTDB_STATE_HEAD_ID`; Unix uses the absolute owner-controlled
`CONTEXTDB_STATE_HEAD_FILE`, outside the archive directory. The authority binds
the canonical path, database identity, commit sequence and exact archive digest
and records active/pending state for crash reconciliation. Replacing an archive
with an older copy while retaining the current authority fails closed. The
authority custodian itself must be protected against rollback; replaying both a
valid old archive and its valid old authority snapshot is outside what a MAC can
detect. `init --force` and `import --force` therefore never overwrite live
anchored state.

The commands above still require supported-platform clean-install receipts; a
dirty Windows development smoke is not one.

The server binds loopback by default. Binding `0.0.0.0` exposes the service and
requires an independently reviewed authentication/TLS/reverse-proxy policy; the
release packaging workstream does not claim a production network perimeter.

Structured health for v1 must combine at least database validity, commit head,
projection watermarks/freshness, degraded/read-only mode, resource pressure and
background work. The current CLI doctor receipt covers only the logical subset.
The authenticated production `get-status` path additionally reports the
closed-world runtime-ledger health paired with the last verified/reconciled
publication, using only a coarse
`runtime_ledger_pressure` band in its content-free profile identifier. It does
not expose tenant or checkpoint counts. Its `capability_manifest` is a
schema-v1 map with explicit `available`, `compiled_only`, and `unsupported`
states for the selected runtime. The map is deliberately honest about the
unwired persistent ANN/Tantivy recall projections, hard delete, live restore,
semantic extraction/adjudication, artifact blobs, and model migration; its
`server_v1_release_ready` value remains false. Provider health, worker backlog,
degraded/read-only causality and projection-specific pressure remain open, so
RFC 31.15 structured-health completion is still not claimed.

The `current-server` HTTP adapter additionally exposes two content-free local
probe endpoints. `GET /health/live` proves only that the HTTP process/router is
responsive. `GET /health/ready` returns 200 only while the production host's
cached publication still matches the current Fjall physical sequence and the
external rollback-authority head; a drift or lost reconciliation returns 503.
These endpoints deliberately require no gateway credential and contain no
tenant, content, path, key, or archive identifiers. The container probe derives
its loopback port from `CONTEXTDB_HTTP_LISTEN` (or uses the explicit loopback
`CONTEXTDB_HEALTH_ADDRESS`) and runs `contextdb probe`, so it never reads the
token/gateway secrets, opens the state archive, or competes for the daemon's
exclusive Fjall/state-head locks.

Both probes include a closed schema-v1 capability manifest. Unlike the
authenticated status profile, the health validator accepts only the fixed
profile labels and the exact public capability vocabulary; extension keys or a
release-ready claim sanitize the response to `not_ready`. This keeps the
manifest useful for orchestration without creating an unauthenticated metadata
channel.

This is a bounded `current-server` readiness slice, not completion of RFC
31.15 or a `server-v1` claim. Worker backlog, degraded/read-only mode,
projection-specific freshness, and provider health remain explicit gaps. See
`runtime-ledger-maintenance.md` for the separately authenticated ledger-health
and retention controls.
