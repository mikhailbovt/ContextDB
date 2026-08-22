# Release engineering

This directory documents the public package, provenance, support, and
verification contracts used to prepare release candidates. It does not declare
that Alpha, Beta, or v1 has passed or been published. Internal planning and
generated source-readiness reports are intentionally kept outside the public
source tree; the retained machine-readable gate ledger does not by itself prove
a release.

Release engineering is split into four evidence levels:

1. **Source** — code, schemas, scripts, Dockerfile, package metadata, and docs
   exist and pass static checks.
2. **Package** — immutable artifacts were assembled, hashed, linked to version
   and provenance manifests, and verified in an isolated directory.
3. **Platform runtime** — the exact artifact passed clean-install and operational
   probes on a declared target.
4. **Publication** — the exact digest is available from the declared registry or
   release URI, carries production signatures and SBOM/provenance, and public
   evidence is retrievable.

One level never implies the next. A Dockerfile is not a Docker image; a local
wheel is not a PyPI release; a checksum is not trusted until a known key signs
it; and an existing proof file is not a passed gate while the ledger says
otherwise.

`assemble-bundle` bridges source/build outputs to the package evidence boundary
without crossing it by wishful thinking. It performs a deterministic offline
copy from a digest-pinned input manifest, but neither creates signatures nor
validates publication or required-platform installs. Its external receipt is
therefore permanently non-release-ready; the release verifier evaluates later
evidence independently.

Two further source-level boundaries close the handoff gap without pretending
that external work happened locally:

- `operational-drill` runs an exact old/new binary pair in disposable trees and
  imports a digest-pinned non-empty seed with the old binary, then records
  side-by-side upgrade, an explicit isolated activation/rollback sequence, and
  disaster-recovery clone/verification. Its receipt is always
  non-release-ready and must later be bound into signed proof.
- `intake-receipts` validates a disjoint, digest-pinned external landing zone
  before evidence enters a new deterministic bundle assembly. It performs no
  network retrieval, runtime probe, copy, signing, or gate update.

Public documents:

- `local-mcp-developer-preview.md` — supported local preview profile and its
  explicit non-claims.
- `artifact-contract.md` — bundle, artifact, checksum, and install-receipt
  contract.
- `signing-and-provenance.md` — signing order, key trust, SBOM, and provenance.
- `package-support.md` — package/platform inventory and clean-install probes.
- `third-party-dependencies.md` — dependency, notice, and SBOM generation
  boundary.

Generated audit/readiness reports belong under `target/` or another explicitly
selected operator output directory. They are not tracked public documentation.

Executable inputs and tools:

- `release/package-matrix.json`
- `release/documentation-matrix.json`
- `assets/schemas/release-*.schema.json`
- `tools/contextdb-release/contextdb_release.py`
- `deploy/release/clean-install.ps1` and `clean-install.sh`
- `deploy/release/operational-drill.ps1` and `operational-drill.sh`
- `.github/workflows/release-candidate.yml` — manual, non-publishing
  candidate-input builds on all declared native targets. It works for private
  or public source but has no publish/sign/Docker step and cannot mark a release
  gate passed.
- `deploy/docker/*`
- `examples/portable-database/*`

Canonical M18/M19 proof paths under `proof/M18` and `proof/M19` are deliberately
not created here. They become valid only after dependency, platform, signing,
security, benchmark, and publication gates really close.
