# ContextDB SDKs

Dependency-light HTTP/JSON clients for the canonical `contextdb-service` v1
contract:

- [`python`](python/README.md) - Python 3.11+, standard library transport;
- [`go`](go/README.md) - Go 1.23+, standard library transport;
- [`typescript`](typescript/README.md) - TypeScript 5.9+, native `fetch`.

All three clients expose the same 59 protected `POST /v1` routes: the legacy
observe/recall/archive surface, typed policy-first ContextPack compilation,
authenticated streaming pages, domain mutation/read/traversal, runtime,
maintenance, status, backup, restore, and migration operations plus the 29
authenticated high-level conversation, memory-control, subject/relationship,
and artifact operations. They preserve strict DTOs, u64 safety, archive octets,
and the complete canonical error envelope.

`get_status` and identity `migrate_format` return a strict schema-v1 runtime
capability manifest. Each client preserves the selected profile, independent
`server_v1_release_ready` flag, and every `available`, `compiled_only`, or
`unsupported` map entry; unknown manifest schemas or states fail closed.
The candidate-only key tuple exported by each SDK is mirrored by the shared
fixture. Those keys describe quarantined proposal storage plus policy-first
candidate recall/DAG traversal only; they do not claim semantic promotion or a
production graph executor.

`RequestContext`, `AuthenticatedRequestContext`, and its nested
`AuthenticationEvidence` are application DTOs, not transport credentials.
Deployment-owned static headers and per-request header providers are explicit
transport options; no client derives gateway assertions from application data.
The official server requires gateway attestation for all 59 routes, including
the six source-compatible `RequestContext` calls. Python, Go, and TypeScript
each expose typed ContextPack request/response DTOs and preserve compiler-owned
trusted control separately from recalled untrusted data. Compile responses also
expose the exact public `CanonicalContextPackV1` bytes and each SDK provides an
explicit BLAKE3-256 verification helper; parsing never silently treats an
unknown encoding as trusted. The
`current-server` router also has unauthenticated, content-free `GET
/health/live` and `GET /health/ready` probes. They are operational host routes,
not SDK operations, and do not establish the full RFC 31.15 or `server-v1`
profile.

Route exposure is not executor support. The reference profile executes pure
runtime preflight with `grants_authority=false`, but its stateful runtime
methods and format migration remain typed gaps. The production CLI backend
implements durable bootstrap/postflight/checkpoint/resume/handoff; postflight
does not verify host/tool execution, and a restart-bound external conformance
transcript remains open. That profile also implements bounded
`production_policy_graph_v1` Reindex, scheduler-owned physical compact
observation, and restart-safe runtime-ledger GC. Reference HTTP remains
`unsupported`; this is not offline repair, lexical/vector/HNSW reindex, or SLO
evidence, and the aggregate maintenance/admin profile remains a gap.

See [`CONTRACT.md`](CONTRACT.md) for the shared route matrix, acceptance
commands, and explicit current boundaries.
