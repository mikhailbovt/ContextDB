# Artifact and checksum contract

## Bundle root

A release bundle is an isolated directory. All manifest paths are normalized
UTF-8, forward-slash, root-relative paths. Absolute paths, drive prefixes,
backslashes, `.`/`..`, duplicate JSON keys, symlinks, duplicate artifact IDs,
duplicate artifact paths, and untracked files fail the release profile. Paths
must be NFC-normalized and portable to Windows: reserved device names,
forbidden characters, trailing dots/spaces, and case-fold collisions are
rejected.

The bundle contains:

```text
release/artifact-manifest.json
release/version.json
release/package-matrix.json
release/proof-index.json
release/signatures.json
release/*.sig
SHA256SUMS
artifacts/...
proof/...
docs/roadmap/gates.json
```

The exact paths are declared by the manifest; the tree above is illustrative.

## Offline assembly boundary

`contextdb-release assemble-bundle` consumes two explicit inputs and records
their digests: `release/package-matrix.json` and a
`contextdb.release-bundle-input/v1` manifest. It never invokes a compiler,
package manager, registry, network client, signing key, Docker, or ContextDB
runtime. Every payload must already exist below `--input-root` and declare its
source path, bundle path, media type, byte count, and lowercase SHA-256. Artifact
entries additionally bind package ID, exact matrix roles/kind, release version,
targets, build-recipe path and related evidence.

`release/bundle-input.example.json` demonstrates the complete schema and matrix
vocabulary without claiming any artifact exists. Its zero hashes and sizes,
dirty all-zero commit, placeholder builder and limitations are deliberate; it
must fail assembly until an operator replaces every reference with real bytes.

The assembler publishes only to a new, non-existing directory outside the input
root. It first builds a private sibling directory, securely copies and checks
each declared regular file, parses structured media, writes the canonical
artifact manifest and checksums atomically, fixes deterministic modes/mtimes,
then renames the complete tree into place. Duplicate/case-colliding paths or
sources, path traversal, links/junctions, unsafe archive members, PEM private keys,
credentials, token-key/state-head sidecars and pre-generated signatures fail
the transaction. JSON payloads, including JSON members inside ZIP/TAR inputs,
are inspected for secret-bearing fields and state-head envelope shape. The
input manifest is evidence about the inputs and is not
silently copied into the distribution.

The assembly receipt binds both source JSON hashes plus the artifact-manifest,
checksum-file and entire-tree hashes. It is deliberately external to the bundle
to avoid a circular checksum. It always records `release_ready: false`, no
network/build/signing/publication/install activity, and the unresolved external
gates. A custodian may subsequently add detached production signatures and
artifact-bound publication/platform receipts. Receipts are incorporated by a
new deterministic assembly into another non-existing output directory; they are
not hand-added to the already checksummed tree. Production signatures are made
only over the final manifest/checksum subjects. Only `verify-bundle --profile
release` with independently supplied public keys can accept those claims.

Before reassembly, `intake-receipts` treats externally generated evidence as an
untrusted quarantine. A `contextdb.release-external-receipt-set/v1` manifest
pins the subject artifact manifest plus every receipt path, byte count, SHA-256,
artifact ID, kind and platform. Operational evidence additionally pins the
exact drill plan and old artifact manifest as quarantined companion inputs. Its
expected coverage set must equal the observed declarations exactly. The subject
bundle and landing zone must be disjoint, the landing-zone inventory must be
exhaustive, and links, path/case
collisions, undeclared files, private keys, custody sidecars, secret-bearing
JSON, digest drift, and schema or artifact-binding drift fail the intake.

An accepted `contextdb.release-external-receipt-intake/v1` report means only
that the pinned bytes are structurally and semantically suitable as inputs for
review and reassembly. It never re-fetches publication URIs, reruns a platform,
copies evidence, creates a signature, or decides release readiness.

## Artifact manifest

`contextdb.release-artifact-manifest/v1` binds:

- semantic version, channel, creation time, repository commit and dirty state;
- the version manifest, package matrix, and proof index by SHA-256;
- the canonical checksum file and detached signature set;
- every artifact ID/package ID/role/kind/path/media type/size/SHA-256/target;
- one version-manifest digest across artifacts;
- source commit, builder, build recipe, and reproducibility declaration;
- related SBOM, install receipt, provenance attestation, publication receipt,
  license and notice files;
- limitations.

The verifier fixes the normative role-to-kind map rather than trusting a
mutable matrix to redefine it: for example server/CLI require an executable,
Python requires a wheel, Docker requires an image, and SBOM requires an SBOM.
Executable, language, adapter, image, example-database, and benchmark-suite
kinds must also declare a runtime probe and at least one runtime target. A
single generically labelled source file cannot satisfy unrelated release roles.

Compiled and distributable artifacts need an artifact-bound SBOM. Beta/stable
artifacts need a detached provenance attestation. Runtime package probes need a
passing install receipt for every required target. Windows best-effort failures
are warnings and remain visible; required-target omissions block a release.
Every release artifact also needs an immutable publication receipt. Receipt,
SBOM and provenance content is parsed and must bind the exact artifact SHA-256;
a correctly labelled arbitrary file is rejected.

## Checksums

`SHA256SUMS` uses exactly:

```text
<64 lowercase hex>__<normalized relative path>\n
```

The two underscores above represent two ASCII spaces. Entries are unique and
sorted bytewise by path. Encoding is UTF-8 without CR separators and the file
must end in LF. The set is exhaustive for artifacts, related files, manifests,
proof files, and the copied roadmap ledger.

The checksum file cannot include its own digest. Detached signatures,
`release/signatures.json`, and `SHA256SUMS` are control files tracked by the
verifier; all other files must appear in `SHA256SUMS`. The checksum file and
artifact manifest are independently signed, so altering either is detectable.

SHA-256 is the release distribution digest. ContextDB logical archives may also
carry a BLAKE3 digest used by the current service/CLI; the two digest roles are
not interchangeable.

## Proof index

`contextdb.release-proof-index/v1` copies no gate status by implication. It
records each milestone, each exit criterion, required proof file hashes,
evidence level, optional platform/public URI, limitations, and known gaps. The
verifier compares it to the hashed roadmap ledger and computes the dependency
closure:

- Alpha requires passed M0–M17 plus passed `M18-E01` evidence.
- Beta requires passed M0–M18 including all M18 exits/proofs.
- Stable requires passed M0–M19 including all exits/proofs.

File presence is not pass status. A report may physically exist while a gate is
failed, incomplete, stale, or unrelated to the exact artifact.

## Verification profiles

The contract profile is for fixtures and source development. Missing release
gates become warnings; explicitly enabled test keys are allowed; and
`release_ready` is always false.

The release profile is fail closed. Any digest/schema/path/signature/proof/
target/install/SBOM/provenance error makes the report non-ready. Only this
profile can return `release_ready: true`.

Verifier and isolated-install outputs conform to
`contextdb.release-verification-report/v1` and
`contextdb.clean-install-receipt/v1`. The latter records generation time,
target, exact non-secret argv, hashed command outputs, a release-version output
check, external-key/state-head boundary checks and whether Docker ran. It uses a
separate authority for every destination, never records key material, authority
selectors/paths, or authority contents, and never treats a contract-profile
fixture as a release.

Upgrade/rollback/DR evidence uses a separate
`contextdb.release-operational-receipt/v1`. A digest-pinned plan binds exact old
and new manifests, versions, binary artifact IDs, host target and verification
profile. New SemVer precedence must be strictly greater, including the standard
prerelease ordering and excluding build metadata from precedence. The plan also
binds one non-empty portable seed artifact and a minimum commit sequence. The
runner copies both bundles, uses one ephemeral token key plus three
distinct external state-head authorities, and performs:

```text
old import of a digest-pinned non-empty portable seed, minimum commit-sequence
check, doctor and export
-> atomically select old
-> new clone-import/doctor
-> atomically select candidate
-> atomically select old and re-export/compare old logical state
-> export candidate for DR
-> new clone-import/doctor recovered state
-> atomically select recovered
```

All activation writes are confined to a disposable supervisor marker. No live
deployment is switched, no destination is overwritten, `--force` is absent,
and exact drill-owned authorities are removed in a `finally` path. A passing
receipt remains runtime evidence for one host, not publication or M18/M19 pass
status. It enters a final bundle as a checksum-bound supporting/proof file
referenced by the proof index; it is not relabelled as a package install receipt.
