# ContextDB release verifier

`contextdb_release.py` verifies release-bundle integrity, package/target
coverage, artifact-bound clean-install/publication receipts, CycloneDX SBOMs,
SLSA provenance, detached Ed25519 signatures, and roadmap proof closure. It uses
no network and never runs Docker.

It also has a deliberately narrower offline assembler. `assemble-bundle` does
not build, fetch, publish, sign, or probe anything. It copies only files named
by a schema-valid `contextdb.release-bundle-input/v1` manifest plus the explicit
package matrix, checks every declared byte count and SHA-256, validates release
version/package/role/target/media bindings, and publishes a new output directory
only after the complete staged tree is ready. Its receipt always says
`release_ready: false`; the independently keyed `verify-bundle --profile
release` pass is the sole path to a positive release claim.

`intake-receipts` is the pre-assembly quarantine boundary for evidence created
on other hosts or by publication jobs. It validates an exhaustive,
digest-pinned landing zone against an exact artifact manifest, including
platform and subject binding for install, operational and publication receipts,
artifact-bound CycloneDX and in-toto/SLSA inputs. Operational intake also binds
the exact drill plan and old artifact manifest. It neither copies the files nor
repeats their runtime/network observation, and its report is permanently
non-release-ready.

`operational-drill` runs exact old/new binary artifacts from separately copied
bundles. It performs side-by-side logical migration, disposable activation,
explicit rollback with old-export identity, and disaster-recovery clone/import
using a digest-pinned non-empty portable seed and distinct external authorities.
It invokes no network command but does not claim OS-level network isolation. It
does not touch a live supervisor, invoke Docker, publish, sign, overwrite a
destination or pass `--force`.

Native probes enforce the CLI's external custody boundary. They use one
ephemeral child-only token key and distinct state-head authorities for the
created and clone-imported databases: unpredictable HKCU selectors on Windows,
or owner-only files outside the copied bundle/data directory on Unix. No secret,
authority selector/path, or authority contents enter the receipt. The probe
never uses `--force` and rejects conventional key/state-head sidecars. Its
`finally` path removes the exact temporary Unix authority directory or the two
exact verifier-owned HKCU subkeys and lock files; a cleanup failure fails the
receipt. The parent registry namespace is never broadly deleted.

The Docker source audit separately requires a non-empty external gateway
identity, a read-only gateway-attestation key bind distinct from the token key,
data and state-head authority mounts, and entrypoint enforcement of exactly one
gateway key source. Static acceptance of that boundary is not a Docker runtime
receipt.

The script targets Python 3.11+ and reports its own semantic version with
`--version`. `jsonschema` and `PyYAML` are runtime dependencies: every trusted
JSON input/generated report is checked against the committed Draft 2020-12
schema, while Compose is parsed with duplicate-key rejection before its
hardening contract is evaluated. Raw Ed25519 verification additionally requires
`cryptography`; absence is a hard verification error rather than a metadata
fallback. The verifier also
enforces the security-critical path, digest, coverage, receipt, signature and
proof semantics that JSON Schema cannot express.

The direct runtime versions used for this source proof are recorded in
`requirements.txt`. This is not a hash-locked wheelhouse or a published
verifier package; final release automation must build and sign that dependency
closure instead of treating four direct pins as supply-chain proof. The BLAKE3
package is required before a Windows child starts so exact HKCU cleanup cannot
be skipped for lack of the CLI's authority-ID digest function.

The two verification profiles are intentionally different:

- `contract` proves that the bundle contract, hashes, paths, and signatures are
  internally valid. It may accept an explicitly enabled test key, reports
  missing release gates as warnings, and always emits `release_ready: false`.
- `release` requires production-trust signatures, required-platform artifacts
  and runtime install receipts, and a passed dependency/proof closure through
  M18 or M19. Only this profile can emit `release_ready: true`.

The verifier does not trust a key shipped inside the bundle. Each trusted
Ed25519 public key must be supplied independently as `KEY_ID=PUBLIC_KEY.pem`.
After canonical path resolution, a trusted key located anywhere under the
bundle root is rejected even when explicitly named on the command line.
The optional Python `cryptography` package is required for cryptographic
verification; the verifier fails instead of falling back to metadata-only
signature checks.

Examples from the repository root:

```text
python tools/contextdb-release/contextdb_release.py assemble-bundle \
  --input-root target/release-inputs \
  --input-manifest target/release-input.json \
  --matrix release/package-matrix.json \
  --output-dir dist/contextdb-0.1.0-alpha.1 \
  --source-date-epoch 1786492800 \
  --report target/contextdb-0.1.0-alpha.1.assembly.json

python tools/contextdb-release/contextdb_release.py audit-source \
  --repo-root . \
  --matrix release/package-matrix.json \
  --report target/release-source-audit.json

python tools/contextdb-release/contextdb_release.py readiness-report \
  --repo-root . \
  --ledger docs/roadmap/gates.json \
  --matrix release/package-matrix.json \
  --stage stable \
  --report target/stable-source-readiness.json

python tools/contextdb-release/contextdb_release.py verify-bundle \
  --bundle-root dist/contextdb-0.1.0-alpha.1 \
  --manifest release/artifact-manifest.json \
  --profile release \
  --trusted-key contextdb-release-2026=/secure/contextdb-release-2026.pem \
  --report verification-report.json

python tools/contextdb-release/contextdb_release.py clean-install \
  --bundle-root dist/contextdb-0.1.0-alpha.1 \
  --profile release \
  --trusted-key contextdb-release-2026=/secure/contextdb-release-2026.pem \
  --report clean-install-receipt.json

python tools/contextdb-release/contextdb_release.py package-example \
  --source examples/portable-database/payload \
  --output target/contextdb-portable-example.zip \
  --report target/contextdb-portable-example.receipt.json

python tools/contextdb-release/contextdb_release.py intake-receipts \
  --subject-root dist/contextdb-0.1.0-beta.1-unsigned \
  --input-root target/external-receipt-quarantine \
  --receipt-set target/external-receipt-quarantine/receipt-set.json \
  --report target/external-receipt-intake.json

python tools/contextdb-release/contextdb_release.py operational-drill \
  --old-bundle-root dist/contextdb-0.1.0-alpha.1 \
  --new-bundle-root dist/contextdb-0.1.0-beta.1 \
  --plan target/linux-operational-plan.json \
  --profile release \
  --trusted-key contextdb-release-2026=/trusted/contextdb-release-2026.pem \
  --report target/linux-operational-receipt.json
```

The input manifest declares separate source and destination paths for the
version manifest, proof index, artifacts, related evidence, and supporting
proof/build-recipe files. `release/package-matrix.json`, the generated
`release/artifact-manifest.json`, and generated `SHA256SUMS` are the only
implicit bundle members. `release/signatures.json` is reserved but absent: a
later trusted signing ceremony creates it and the detached signatures.

An abridged, deliberately non-runnable shape (digests and sizes must be computed
from the actual inputs) is:

```json
{
  "schema_version": "contextdb.release-bundle-input/v1",
  "release": {
    "version": "0.1.0-alpha.1",
    "channel": "alpha",
    "created_at": "2026-08-12T00:00:00Z",
    "candidate": 1
  },
  "source": {
    "repository": "https://example.invalid/contextdb",
    "git_commit": "1111111111111111111111111111111111111111",
    "dirty": false
  },
  "version_manifest": {
    "source_path": "metadata/version.json",
    "path": "release/version.json",
    "sha256": "<64 lowercase hex from metadata/version.json>",
    "size_bytes": 1234,
    "media_type": "application/json"
  },
  "proof_index": {
    "source_path": "metadata/proof-index.json",
    "path": "release/proof-index.json",
    "sha256": "<64 lowercase hex from metadata/proof-index.json>",
    "size_bytes": 5678,
    "media_type": "application/json"
  },
  "artifacts": [],
  "supporting_files": [],
  "limitations": ["example shape only; not a releasable manifest"]
}
```

The schema requires at least one artifact; the intentionally incomplete snippet
cannot be mistaken for an assemblable release input. Each real artifact uses
the same source/path/hash/size/media fields and also declares `id`, `package_id`,
exact matrix `roles`/`kind`, `targets`, `version`, `provenance`, and
`related_files`. `release/bundle-input.example.json` is the complete,
schema-valid counterpart: its all-zero hashes, zero sizes, dirty source and
explicit limitations intentionally make it non-assemblable and non-releasable.

Input paths and archive member names are normalized and checked for traversal,
case collisions, duplicates, symlinks/junctions, state-head authority data,
key/credential sidecars, PEM private-key content, and pre-generated signature
material. The manifest, matrix, direct JSON inputs and JSON members inside
ZIP/TAR inputs also reject secret-bearing fields and state-head envelope shape.
Structured JSON/text/ZIP/TAR/gzip inputs are parsed rather than
accepted only by filename; native executables are checked for target-appropriate
PE/ELF/Mach-O magic. Opaque `application/octet-stream` payloads remain bound by
their exact digest, size, package kind, version, and targets.

ZIP and TAR validation is intentionally bounded to 100,000 members and 4 GiB of
expanded data per input; ZIP expansion ratios above 10,000:1 are rejected. The
input manifest and matrix are limited to 16 MiB each, while directly parsed
JSON/text members are limited to 256 MiB. Larger payloads must use an appropriate
stream-validated archive or opaque binary media type and remain digest-pinned.

`--source-date-epoch` and `SOURCE_DATE_EPOCH` are equivalent; a conflicting pair
fails closed. Without either, the manifest's whole-second `release.created_at`
is used. Generated JSON/checksum bytes, bytewise path order, permissions, and
file/directory mtimes are deterministic. Pre-built package/archive bytes are
never recompressed, so identical declared inputs produce byte-identical bundle
files and the same tree digest. The existing `package-example` command provides
the deterministic portable-example ZIP step when that package is required.

Unit tests:

```text
python -m unittest discover -s tools/contextdb-release/tests -v
```

The manual `.github/workflows/release-candidate.yml` job executes these source
contracts and builds unsigned, non-publishing candidate inputs on required Linux
x86_64, Linux arm64 and macOS arm64 runners plus visible best-effort Windows
x86_64. It works for either repository visibility and uploads short-retention
workflow artifacts only. Its build record explicitly states that no production
signature, publication, Docker execution, platform install receipt or release
decision occurred.
The generated SBOM/provenance files are unsigned, self-asserted candidate
metadata until an independent builder/attestor creates the final evidence.

The committed release schemas live in `assets/schemas`, including schemas for
verification and clean-install reports. The tool performs the security-critical
semantic checks itself. CI/unit tests validate every schema and canonical
instance so schema tooling and verifier semantics cannot silently drift. The
test suite includes both fail-closed adversarial cases and a complete synthetic
production-trust fixture that must be capable of reaching `release_ready: true`;
this prevents an accidentally impossible verifier from looking secure merely
because it rejects everything.
