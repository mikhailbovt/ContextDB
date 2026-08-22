# Benchmark result format

ContextDB benchmark evidence is a versioned artifact, not a pasted table. Each run validates against [`assets/schemas/benchmark-result.schema.json`](../../assets/schemas/benchmark-result.schema.json) and records:

- benchmark family, scenario, dataset version, and tier;
- exact ContextDB/version-manifest identity;
- hardware, OS, architecture, filesystem, storage backend, compiler, and build profile;
- deterministic seed, budgets, feature set, parameters, and index watermarks;
- model, prompt/schema, and embedding revisions when a model-assisted stage participates;
- raw artifact digests and metric summaries;
- thresholds, direction, pass/fail result, limitations, and errors.

Metrics without a predeclared threshold remain observations and cannot pass a release gate. A result that omits required environment or version information is non-reproducible and cannot be used to change an ADR.

Every `quality_gates[].metric` binding must resolve to one unique emitted metric
with a threshold, and the gate outcome must equal the metric's evaluated
threshold outcome. Artifact kind/URI bindings and metric and gate identifiers
must also be unique. A loose boolean next to an absent or informational metric
is invalid evidence.

The M17 semantic intake uses
`contextdb.bench-h-semantic-outcome/v1`. It requires an exact three-tier by
ten-scenario matrix, raw bounded samples, the RFC/ERRATA scale floors, four
numeric frozen-quality comparisons, and content-addressed reference-hardware,
scenario, resource, and regression artifacts. Coverage and E01/E02/E03 results
are derived by the crate; the input has no completion/pass booleans. A bound
hardware-profile artifact identifies the measured host but does not prove that
the profile was published or independently witnessed. The
current evaluator is deliberately `native_measured_development`: it cannot
accept M16 or release-candidate assertions and cannot emit a release pass.

The executable semantic runner is a separate, narrower evidence source. Its
first command writes `semantic-admission.json`, binding exact requested counts,
the measured host capacity, conservative disk/RAM/ETA estimates and every hard
blocker. The run command reads that same artifact and requires its SHA-256; it
does not accept new scale arguments. Counts in
`contextdb.bench-h-semantic-execution/v1` are populated only after exhaustive
graph reads, vector-store restore and digest verification. Supporting traces
are written first and content-addressed in the outcome; a small final bundle
index then content-addresses the outcome itself.

Current certification admission no longer reports a graph-format or missing
ANN-runtime blocker. Graph-v2 admits the required 200 million directional
records, and executable smoke builds, completely verifies, closes, reopens,
authorizes, and searches a redb-backed persistent ANN-v2 generation. The
content-addressed ANN receipt binds publication/reopen storage sequences,
manifest digest and physical counts, policy-before-vector counters, private-ID
isolation, and exact ID/score differential results.

Certification still fails closed for two ANN source/evidence limits:

- full-precision vectors and routing policy are supplied by the intentionally
  in-memory `VectorIndexAnnSourceV2` development bridge, not a durable paged
  source suitable for the 1M-vector floor; and
- no accepted reference-hardware receipt yet proves ANN-v2 construction
  throughput, recall, latency, and exact-oracle quality at one million vectors.

Host capacity is evaluated separately on every admission. On the final local
preflight, the 770,688,000,000-byte disk estimate also exceeded the
583,050,746,265-byte 80%-safe envelope derived from 728,813,432,832 bytes of
current free space. That
host-specific blocker is serialized beside the source blockers; it is not
silently waived by confirmation.

Example commands:

```text
cargo run --release --locked -p contextdb-bench -- \
  --semantic-admission --output <fresh-directory> --preset smoke

cargo run --release --locked -p contextdb-bench -- \
  --semantic-run --output <same-directory> \
  --confirm-admission <printed-sha256>

cargo run --release --locked -p contextdb-bench -- \
  --semantic-admission --output <fresh-directory> --preset certification-v1
```

The last command writes estimates and blockers only. It cannot start the full
10M/100M/1M run, even if somebody tries to "confirm" the blocked digest. A
successful smoke `persistent_ann_v2_runtime_exercised=true` is derived only
after the redb generation, complete verification, reopen, authorization, search,
and exact differential receipt all pass; caller metadata cannot set it.

See [`examples/m0-governance-validation.json`](examples/m0-governance-validation.json) for a schema-valid structural example. It is not performance evidence.
