# Security Policy

ContextDB stores unusually sensitive long-lived state. Please report suspected vulnerabilities
privately to the maintainers before public disclosure. Until a dedicated security address is
published, use a private security advisory in the canonical repository.

## Supported versions

No stable release exists yet. Security fixes target the latest development branch and the newest
published pre-release when practical.

## In scope

- cross-space, cross-subject, or cross-tenant disclosure;
- authorization-after-retrieval or ranking/timing leakage;
- prompt injection that gains instruction or tool capability;
- memory poisoning, fabricated evidence, or unauthorized semantic mutation;
- incomplete hard deletion or secret persistence in projections, caches, exports, or backups;
- corruption, partial commit, acknowledged data loss, unsafe restore, or archive tampering;
- confused-deputy behavior among actor, agent, subject, workspace, and purpose;
- parser, format, continuation-token, model-gateway, and adapter vulnerabilities.

## Reporting guidance

Include the affected revision, deployment mode, minimum reproduction, expected policy, observed
behavior, and whether sensitive data was exposed. Do not attach real secrets; use synthetic values.

## Security invariants

Authorization and purpose restriction occur before candidate generation. Retrieved content is data
without instruction capability by default. Model output is quarantined and schema/evidence/policy
validated. Primary state is recoverable without derived indexes. Deletion suppresses recall at the
semantic commit and later reclaims every governed derivative through lineage.

The implementation threat model is maintained in
[`docs/security/threat-model.md`](docs/security/threat-model.md). Normative release gates remain in
RFC-0001 sections 26, 28, and 31. A pre-release build must not claim M16 while the threat model's
known-gap list or the machine-readable milestone proof reports an unresolved critical/high finding.
