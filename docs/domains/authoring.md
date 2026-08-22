# Authoring a ContextDB domain pack

A domain pack maps external evidence into universal ContextDB semantics without
adding application-specific dependencies or provider assumptions to the core.
`contextdb-domain-code` is the reference implementation.

## Required shape

A pack should contain:

1. a stable reverse-DNS or crate-qualified pack identifier and version;
2. strict input DTOs with unknown-field rejection and bounded sizes;
3. an adapter that validates exact source bytes, identities and provenance;
4. domain records represented through `NodeType::Domain` plus a core
   `SemanticEnvelope`;
5. deterministic identity and revision rules;
6. policy-first query/projection seams;
7. canonical export/import validation;
8. adversarial fixtures and a frozen domain benchmark.

The dependency direction is pack to core. `contextdb-core` must not depend on a
domain pack, parser, compiler, model SDK or network client.

## Identity and revisions

Choose public IDs from canonical domain identity, not file offsets, vector
neighbors or model guesses. If a rename/move match is ambiguous, create a new
identity or quarantine the proposal. A revision must name its parent and exact
source snapshot; stale-parent publication fails atomically.

Domain time and transaction time remain distinct. Preserve historical source
snapshots and never rewrite evidence to make a new interpretation look old.

## Evidence and provenance

Every promoted fact or relationship needs exact evidence: artifact/revision ID,
byte range or structured source location, digest, extractor/parser version and
lineage. Revalidate ranges against immutable bytes. Summaries and model output
are derived evidence and cannot self-support their own promotion.

When rationale or support is missing, return `Unknown`. Do not infer intent from
a commit message, ticket title or generated summary without policy-authorized
evidence.

## Policy boundary

The host authorizes workspace, subject, scope, audience, purpose and evidence
before the pack receives source content. The pack propagates the exact policy
or a stricter one to derived nodes, relations and indexes. It must prove that
adding forbidden source material does not affect authorized results.

## Model/provider boundary

Parsers and model extractors are upstream proposal adapters. Their output must
pass a strict schema and deterministic validation before becoming a domain
record. A pack may operate entirely with deterministic parsers and must never
require provider credentials in the database core.

## Compatibility checklist

- Never reuse an existing kind or field with new meaning.
- Additive optional fields require defaults that preserve old behavior.
- A new authoritative kind or identity rule requires a pack-version bump.
- A destructive archive change requires an explicit migrator and golden
  old-to-new fixtures.
- Unknown enum values fail closed unless capability negotiation explicitly
  permits them.
- Stable public IDs survive rebuild, compaction and runtime migration.

## Acceptance checklist

- malformed, duplicate, cyclic and cross-tenant inputs fail atomically;
- import reproduces the same logical digest;
- current, historical, conflict and unknown queries have fixtures;
- unauthorized inputs have zero influence;
- benchmark inputs, thresholds, version manifest and result schema are frozen
  before a qualifying run;
- limitations and unsupported languages/formats are explicit.
