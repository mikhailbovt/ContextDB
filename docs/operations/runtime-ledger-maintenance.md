# Runtime ledger maintenance

The `production-fjall-v1` profile has a bounded, synchronous maintenance slice
for durable runtime lifecycle state. It is operational retention, not hard
deletion and not a security erasure claim.

## Content-free health

An authenticated `get-status` request reports the complete runtime-ledger
health captured with the last fully verified and externally reconciled
publication. A successful production profile string includes
`verified-runtime-ledger-health-v1` and one coarse pressure band:

- `nominal`: below 70% of the closed-world runtime-record cap;
- `elevated`: at least 70% and below 90%;
- `critical`: at least 90% and below 100%;
- `exhausted`: the admission cap has been reached.

The response contains no workspace, subject, agent, checkpoint, operation or
record identity and no checkpoint/ContextPack bytes. A later unverified
disk-only change does not alter ordinary published reads: `/health/ready`
detects the physical-sequence drift, and explicit `verify` inspects it and
returns a typed integrity error instead of publishing a nominal successor.

## Bounded GC

Call the existing `compact` maintenance operation with an exact payload:

```json
{
  "action": "runtime_ledger_gc",
  "schema_version": 1,
  "retain_state_versions": 64,
  "max_record_work": 10000,
  "dry_run": true
}
```

`retain_state_versions` is inclusive `2..=4096` per runtime identity.
`max_record_work` is inclusive `1..=100000` and bounds state deletes,
checkpoint-head deletes, receipt rewrites and anchor writes in one synchronized
transaction. Run a dry plan first, then repeat with `dry_run: false`.

An applied pass:

1. verifies the closed-world key layout, complete runtime state chains,
   checkpoint heads, receipts, durable history and external authority;
2. removes only an oldest state prefix while retaining the configured tail;
3. writes a keyed, content-free accumulator anchor over the removed prefix;
4. clears potentially large response bytes from receipts that referenced the
   removed states while retaining their keyed request/response commitments;
5. stores one content-free receipt for the maintenance operation itself;
6. publishes one synchronized durable-root successor and reconciles it with the
   external anti-rollback authority before acknowledging.

An applied request, including an already-converged `no_op`, records exactly one
maintenance receipt. Retrying the same operation ID and canonical bounds
returns that receipt with `replayed: true` and does not run another pass. Reusing
the ID with different bounds or authority returns `idempotency_conflict`.
Dry-runs remain read-only and do not reserve an operation ID.

An exact retry of a retired lifecycle operation returns
`continuation_expired` with policy `runtime_ledger_retention`. A changed request
under the same operation ID still returns `idempotency_conflict`. The old ID is
never allowed to alias a new lifecycle transition. The compacted store and its
anchors are verified again on every restart.

Receipts remain as small content-free operation tombstones. This preserves
non-aliasing but means arbitrary operation identities cannot be admitted
forever: the global record cap remains fail-closed. GC reduces retained
checkpoint/ContextPack payload history; it does not claim an unbounded ledger.
The work budget covers runtime state deletes, checkpoint-head deletes, lifecycle
receipt rewrites and anchor writes; the single maintenance receipt, rooted
counter and durable-head successor are fixed transaction overhead.

## Physical compaction boundary

The exact physical observation payload is:

```json
{
  "action": "physical",
  "schema_version": 1,
  "max_bytes": 1048576
}
```

Fjall currently schedules LSM compaction in its own supervisor. The response
therefore reports `scheduler_managed: true`, verifies that the logical sequence
did not change and reports only bytes the adapter can prove were reclaimed
(currently zero). It does not claim a synchronous manual rewrite.
