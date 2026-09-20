# Format and version compatibility

ContextDB versions five compatibility axes independently:

| Axis | Covers |
| --- | --- |
| wire | HTTP JSON and Protobuf/gRPC request/response contracts |
| semantic | public IDs, envelopes, mutation and evidence meaning |
| storage | physical backend/journal layout and recovery rules |
| ContextPack | canonical compiled context and renderer contract |
| MCP | stateless discovery, metadata, result and cache semantics |

The active values are declared in `version.toml` and embedded in a canonical
version manifest. A package version alone is not enough to decide compatibility.

## Canonical encodings

Canonical JSON uses deterministic field ordering supplied by typed serializers,
rejects duplicate/unknown fields at trust boundaries and is re-serialized before
digest comparison. Binary blobs in the HTTP contract are arrays of bytes unless
the schema explicitly declares another representation.

Canonical Protobuf never reuses a released field number. Unknown additive fields
may be preserved/ignored according to Protobuf rules, but an unknown operation or
capability never gains authority by default.

`ContextPack` canonical JSON and Protobuf represent the same semantic pack. A
round trip must retain the snapshot, filter, evidence, conflicts, unknown state,
budgets and digest.

The public canonical encoding identifier is
`contextdb.context_pack.protobuf.v1`; its normative Protobuf message is
`contextdb.v1.CanonicalContextPackV1`. A compile response exposes those exact
bytes and identifies `blake3-256` as the digest algorithm, so a remote client
can verify the returned digest without reproducing implementation-specific
serialization.

## Logical archives

A logical archive contains canonical semantic state and retained content needed
for deterministic import. Its format identifier and exact digest are verified
before mutation. Import is clone-only into an empty target in the current CLI;
live overwrite and `--force` are disabled.

A logical archive is not a physical checkpoint, encrypted backup, signature or
proof of freshness. Those are separate envelopes and operational workflows.

### Local administrative backup envelopes

`contextdb.native-fjall.logical-backup.v1` is the bounded canonical logical
snapshot of the native service's admitted keyspaces. Its binary schema fixes the
native storage-format identity, database identity, global commit, deep logical
digest, exact ordered keyspace set, strictly ordered length-prefixed rows, and a
BLAKE3 footer. Readers reject unknown/missing/reordered keyspaces, duplicate or
unordered keys, trailing bytes, non-canonical re-encoding, violated entry/count
or byte caps, and broken policy/content/event/workspace closure.

Native continuous archives use `contextdb.native-fjall.logical-backup.v2`.
The optional encrypted profile uses `contextdb.native-fjall.encrypted-backup.v3`:
the same ordered row framing carries authenticated ciphertext and an exact key
authority ID. It requires the retained external key inventory, master key and
current suppression ledger; none is imported from the backup. Logical closure
is verified through a decoding view before restoring a pristine encrypted target.
Explicit source, assertion and payload pruning have separate manifest features
and accepted journal records. Assertion pruning retains independent mutations in
a distinct representation, bound to the original receipt and accepted control
hashes; it never claims rewritten bytes have the old full-batch digest. Tombstones
and chunk progress permit only declared missing bodies. The deep digest still
hashes every actual remaining row. A partial
cleanup archive is not a completion receipt or evidence of physical erasure.
The `continuous-record-sources-v1` feature binds native applied provenance to
an independently retained version 3 suppression authority. Its global genesis,
workspace chains and revision indexes are mandatory; record bodies and origin
controls keep their original commitments. Native restore never replaces this
registry. An older archive must catch up before disclosure, and unclassified
records remain unavailable. Older authority versions require explicit migration.
The header and record addresses are visible; the format does not claim signatures,
physical erasure or production host key custody. See the
[native encryption and restore contract](architecture/continuous-context.md).

`contextdb.codex-composite-backup.v1` is a local host envelope containing one
canonical `contextdb.logical.v1` lifecycle component and one native backup
component. Its schema embeds the immutable restore policy identifier
`lifecycle-exact-match+native-pristine-target-only`, exact component formats,
digests and commit sequences, database identity, and its own BLAKE3 footer. A
reader must reproduce the exact canonical encoding. This format is deliberately
not a subject export, encrypted backup, signed artifact, token-key container,
external state-head snapshot, or production runtime-ledger checkpoint. The
restricted operator protocol is documented in
[`backup-restore.md`](operations/backup-restore.md).

## Storage formats

The storage engine exposes ordered keyspaces, snapshots, atomic write
transactions, explicit durability, verification, checkpoint capability and
physical compaction. The semantic format does not expose backend sequence
numbers, dense IDs or LSM page layout.

A backend swap or index rebuild must reproduce the same canonical logical digest.
Unsupported historical snapshots, online checkpoints or physical deletion are
reported as capabilities; they are never silently emulated with weaker meaning.

## Change policy

An additive change is compatible only when old readers remain safe and old
values keep their meaning. The following require a new relevant format version:

- changing an existing field's meaning or validation;
- weakening authorization, evidence or lineage rules;
- changing canonical identity derivation;
- removing a required field or enum variant;
- changing archive digest domains or transaction semantics;
- making previously ignored data executable/authoritative.

Migration is explicit: analyze source/target manifests, seal a checkpoint,
perform required rebuilds or re-embedding, compile a target bootstrap, run
pre/postflight checks, verify, then atomically activate. Unsupported migration
returns a typed error and leaves the source untouched.

The reusable `contextdb-format::FormatRegistry` performs the fail-closed reader,
required-feature, path and free-space portion of that preflight. It produces an
ordered immutable plan; it does not claim that a host migration executor or an
activation receipt exists.

## Release candidate rule

The repository currently exercises additive-compatibility fixtures and exact
current-format archive round trips. A v1 format candidate is not frozen until
M18 publishes cross-version migration, rollback and supported-platform receipts.
