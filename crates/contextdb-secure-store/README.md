# contextdb-secure-store

`contextdb-secure-store` is an isolated, non-production hard-delete v2
foundation. It defines content-key, composite-head, deletion-workflow,
closure-inventory, receipt, and ciphertext-only export contracts without
wiring them into `ProductionService`.

The crate is intentionally not a claim that hard deletion is available. It now
contains a local redb-backed P5 durability slice, a real local master-key-backed
crypto/recovery adapter, and P6 workflow/read bridges. Production still requires
qualified key custody or external KMS/HSM and repository authorities,
caller-custodied anti-rollback state, physical-media purge verification, real
managed-provider evidence, and service wiring under one proven authority root.

## Implemented foundation and local source slice (P0-P5/P6 bridge)

- random per-object/per-erasure-domain DEK contracts with no key-byte export;
- database/workspace/record-kind/owner/policy/key-revision AEAD binding;
- `Active -> DestroyPending -> Destroyed` monotonic key catalog;
- MACed composite four-root head with namespace-bound monotonic CAS and
  fail-closed pending suppression;
- exact 13-class deletion closure and monotonic eight-state workflow;
- external suppression, evidence, receipt-signing, and verification traits;
- signing-key generation in signed receipt contracts;
- byte-bounded workflow recovery and streaming ciphertext export manifests;
- attested authority provenance with expiry, revocation, and mandatory
  per-operation freshness checks on integration-eligible adapter views;
- idempotent asynchronous key-destruction, rollback-resistant chained head
  repository, and managed-copy deletion adapter contracts;
- explicit `OutsideControl` terminal-incomplete semantics and a trust gate that
  can never enable production hard delete from non-production adapters;
- caller-preallocated durable object identities and idempotency intents that
  are persisted before KMS I/O;
- a monotonic `Reserved -> KeyCreated -> ObjectStored -> PublicationPending ->
  Published` encrypted-object/key-catalog recovery contract;
- atomic ciphertext plus key/catalog create-or-get, exact provider/export/backup
  inventory commitments, stable-generation point/page APIs, and an exact P3
  composite-head retry intent;
- explicit recovery actions for KMS-created-before-store and
  store-created-before-head crashes, with no synthesized head or erasure
  receipt;
- a redb-backed encrypted-object catalog that commits every mutation in one
  immediate-durability transaction, revalidates provenance-bound persisted
  publication intents, recomputes catalog roots from disk, and checks a chained
  full-state generation history against an optional caller-custodied rollback
  anchor;
- process-kill coverage for committed versus uncommitted redb reservations,
  plus reopen recovery at every encrypted-object creation stage;
- `LifecyclePayloadV1`, a bounded, deny-unknown metadata envelope binding exact
  workspace, agent, subject, audience, scope, profile, tool, and provenance;
  `ModelHiddenReasoning` is explicitly rejected on construction and recovery;
- `RedbLocalCryptoAuthorityV1`, a non-test XChaCha20-Poly1305 adapter with an
  externally supplied, non-serializable zeroizing master key, random wrapped
  per-object DEKs, idempotent create/describe/destroy, keyed store binding, and
  an authenticated generation chain checked against an optional external
  rollback anchor;
- crash-safe encrypted source staging: the source is committed only as AEAD
  ciphertext under a random wrapped staging key, final DEK/object commit and
  staging removal are atomic, and bounded opaque recovery pages can converge a
  crash after DEK allocation without returning source plaintext;
- complete object and staging records are themselves stored in an authenticated
  master-key envelope, so lifecycle labels and source metadata do not appear as
  plaintext redb values; only opaque table keys, commitments, generations, and
  keyed authenticators remain outside that envelope;
- a local open API with no raw `KeyAuthorityV2` implementation: authenticated
  publication and suppression run before permit issuance, and every permit use
  must cross `LocalOpenAuthorizationEpochV1`; that coordinator compares the
  exact current authenticated publication/suppression epoch and holds its shared
  lease while the authority rechecks descriptor, revision, key, context, unwrap,
  and decrypt. Suppression publication takes the matching exclusive lease, so a
  permit use linearizes entirely before it or fails after it; destruction is
  separately serialized and revokes permits through the durable reread;
- an authenticated read gate that denies pending suppression before consulting
  the overlay or key authority, checks enforced suppression before DEK access,
  and binds the exact ciphertext to its persisted descriptor;
- managed-copy workflow bridges that require independent pre-I/O request
  persistence, durable-ticket proof, and current signed terminal evidence;
  `OutsideControl` is recorded but remains incomplete;
- test-only in-memory authorities behind `test-support`.

The P3 authority/repository adapter traits are backend transport contracts;
only their `Current*V2` views are integration-eligible, and those views consult
the host's current trust/revocation decision before every operation. The redb
catalog is a real local disk adapter, but it is not a production capability or
an integration-eligible authority. Its generation chain detects corruption and
an externally retained exact anchor detects rollback; without independent
anchor custody, a whole-database rollback cannot be distinguished. The
in-memory authorities remain deliberately non-production and provide no
HSM/KMS isolation, external-media proof, or provider deletion receipt.

`RedbLocalCryptoAuthorityV1` is a meaningful local runtime boundary, not a
custody certification. The caller must protect the database directory with
platform ACLs, source the master key from external secret custody, never place
that key beside the database, and retain each returned anchor independently.
The adapter intentionally does not claim DPAPI, Linux keystore, KMS, or HSM
backing. Its synchronous `destroy` removes the live wrapped DEK and makes prior
permits unusable, but redb pages/copies, ciphertext, backups, and managed copies
remain explicit deletion targets requiring separate physical/provider closure.

See the public [threat model](../../docs/security/threat-model.md) and
[limitations](../../docs/limitations.md) for the remaining integration,
custody, and physical-deletion boundaries.
