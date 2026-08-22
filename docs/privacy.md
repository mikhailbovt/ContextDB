# Privacy, consent, retention and deletion

This document describes the privacy contract implemented by ContextDB
components. It does not replace a deployment's legal basis, retention policy or
key-custody procedure.

## Authorization before influence

Policy metadata is stored separately from erasable content so authorization can
run first. A denied record must not affect candidate generation, graph traversal,
ranking, traces, continuations, watermarks or context size. Filtering a result
after retrieval is insufficient because it leaks existence and influence.

The authorization decision binds workspace, subject, memory space, scope,
audience-purpose grant, actor/agent/session, clearance, consent and snapshot.
Derived summaries and indexes may only preserve or narrow those constraints.

The in-memory reference profile treats workspace indexes as security state.
Candidate and event selection starts from the authenticated workspace, has a
strict work/page budget, and has no global-corpus fallback. Every write updates
the indexes before publication; logical import rebuilds them from trusted
non-content metadata and verifies exact membership. Record workspace membership
is immutable across revisions.

Caller-facing typed point and timeline reads resolve authorized non-content
metadata first. Absent, tombstoned, wrong-family, policy-denied and missing
family-capability outcomes have one content-free external error; evidence or
conflict content is not materialized until its exact stored family capability
has been established. Legacy Observe has no policy-minting authority: its
submitted access label must exactly match the private, same-subject policy
derived from the authenticated workspace, scopes and purpose.

Recall, timeline and traversal snapshots/watermarks, plus subscription event
positions, use gap-free workspace-local sequences. Zero is workspace genesis;
each positive snapshot ordinal maps to the exact corresponding internal commit
for that same workspace. The numbers are not portable across workspaces, and a
different workspace's writes cannot advance them. Subscription cursors are
opaque, authorization-bound and versioned by this sequence domain.

Suppression and audience changes are current-use policy, not a way to rewrite
what the system historically knew. The executable semantic-control profile
publishes a new bitemporal lifecycle/policy revision while preserving the
target's immutable value, evidence links and earlier revisions. Current policy
then overlays every retained semantic snapshot before lexical, vector, graph,
point or timeline materialization; an old commit cannot resurrect a currently
suppressed or unauthorized memory.

## Data minimization

- Provider requests contain only the selected, authorized context and declared
  modality.
- Telemetry labels are fixed, low-cardinality enums; payloads and identities are
  not labels.
- Audit/debug output is redacted and payload-free by default.
- Secret scanning runs before persistence or external processing. A vault URI
  must match a strict opaque-handle grammar and contain no inline secret.
- Public integrity metadata must not provide an offline oracle for guessing
  low-entropy restricted plaintext.

## Restricted content

`contextdb-security` provides application-level AEAD for restricted fields. The
associated data binds database, workspace, record, field, scopes, policy and key
generation. Authorization and metadata checks occur before decryption.

Using the security primitive is a host obligation. A logical archive or storage
backend is not automatically encrypted merely because the primitive exists.
Release evidence must prove the concrete executable composition and key custody.

## Retraction and hard deletion

Retraction keeps content and history but marks the semantic value inactive.
Hard deletion removes all authoritative content indirections and produces a
minimal tombstone/evidence receipt. Completion requires an authoritative closure
inventory across primary state, journals, indexes, caches, backups and providers;
one adapter saying "done" is not sufficient.

Derived indexes must be invalidated before deleted content can reappear. Old
snapshots and restored backups are constrained by a current, externally anchored
live-policy overlay. Physical media reclamation and crypto-erasure are separate
proof obligations.

## Export, backup and restore

A portable logical export is not necessarily an encrypted backup. Secure backup
envelopes bind database/workspace, subject partitions, scopes, policy, parent,
expiry, encryption/signing key IDs and generations. Restore authorization is
evaluated before decryption and must merge current revocation/deletion policy.

Restore targets are empty staging databases. Deep verification precedes atomic
activation. Replacing a live database with an old self-authenticating archive is
rollback, not restore.

## Key and authority custody

The CLI requires externally supplied token and state-head authority. Secrets are
not stored beside the database or written to receipts. On Windows the current
development contract uses a per-user external authority; on Unix it requires an
owner-only external path. A coordinated rollback of both data and its external
authority cannot be detected by a MAC alone and requires a monotonic OS/KMS/HSM
custodian.

## User-facing controls

Applications must distinguish request, confirmation, execution and verified
completion. A UI may queue correction, retract, forget, privacy or share actions,
but it must not display `Applied` until the authorized executor returns a durable
receipt covering the requested closure.

The current generic logical profile executes Suppress, exact ChangeAudience,
and exact shared-audience publish/revoke. Control DTOs are bounded and reject
unknown fields. Pin and ChangeRetention remain unavailable because this archive
has no lossless pin/retention policy field; storing either in erasable
attributes would evaluate policy after protected payload and is forbidden.
Subject export/import likewise remain unavailable until a profile can prove a
complete filtered lineage closure and collision-free atomic isolation.

## Current release boundary

Security primitives, adversarial tests and a sealed static repository scan exist,
but final v1 privacy status also requires verified remediation of that scan,
concrete production composition, supported-platform key-custody receipts,
deletion/restore integration and public release proof. The roadmap must remain
open while any of those gates is open.
