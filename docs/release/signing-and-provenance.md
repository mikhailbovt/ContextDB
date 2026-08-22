# Signing, SBOM, and provenance

## Canonical signing order

1. Build immutable artifacts in declared builders from one clean source commit.
2. Produce artifact-bound SBOMs, SLSA provenance and clean-install receipts.
3. Publish the immutable payload artifacts, retrieve them from the public
   registry/release endpoint, verify bytes, and write publication receipts.
4. Freeze the version manifest, package matrix, copied ledger, and proof index.
5. Write the final artifact manifest with exact sizes and SHA-256 values for the
   artifacts and every receipt/attestation.
6. Write canonical `SHA256SUMS` over every payload, manifest, proof, receipt,
   SBOM and attestation.
7. Sign the raw bytes of the artifact manifest and checksum file. Beta/stable
   additionally sign the proof index and version manifest.
8. Write `release/signatures.json` with each detached signature digest, key ID,
   DER-SPKI SHA-256 fingerprint, role and trust class.
9. Verify the final bundle from a separate directory with independently obtained
   public keys. Re-fetching public artifacts remains a publication job, not an
   offline-verifier side effect.

The selected algorithm is raw detached Ed25519. Public-key fingerprints are
SHA-256 of the DER `SubjectPublicKeyInfo`, not PEM text. Signature files contain
exactly the raw 64-byte Ed25519 signature.

## Trust boundary

The verifier never promotes a key merely because it is in the bundle. Operators
supply `KEY_ID=PUBLIC_KEY.pem` through an independent channel. A matching key ID
or fingerprint without cryptographic verification is insufficient. After
canonical path resolution, a trusted-key path under the bundle root is rejected.

Test keys require both the contract profile and `--allow-test-keys`. They can
exercise encoding, tamper detection and rotation mechanics, but can never make a
release ready. Production private keys, HSM/KMS configuration, identity review,
revocation, threshold policy and incident procedure remain outside this source
tree.

## SBOM

The v1 artifact set needs an SBOM, and each executable/package/image artifact
must link to the SBOM that describes its actual contents. The selected wire
format is [CycloneDX JSON](https://cyclonedx.org/docs/latest/json/) 1.5 or 1.6.
The verifier requires the root `metadata.component.hashes` SHA-256 to equal the
artifact digest. The checked-in `release/contextdb-local-mcp.cdx.json` describes
only the narrow unsigned developer-preview dependency graph; release-candidate
CI generates fresh binary- and wheel-bound SBOMs. Neither substitutes for a
final signed multi-artifact release SBOM.

## Provenance

The artifact manifest records source commit, builder and recipe. Beta/stable also
require a detached [in-toto Statement v1 carrying SLSA provenance
v1](https://slsa.dev/spec/v1.2-rc2/build-provenance), linked by digest. The
verifier requires the declared build recipe to exist and enter the signed
checksum closure, and requires the attestation subject path/SHA-256 plus one
resolved source dependency to match the artifact and source commit. This selects
a wire contract; it does not invent a production signer or claim a SLSA level.

## Install and publication receipts

`contextdb.clean-install-receipt/v1` binds every actually exercised artifact by
ID, path, version, and SHA-256. All recorded probes must pass in an isolated
copy. Native probes inject one ephemeral token-key source and independently
select an external state-head authority for each created destination; neither
secret/authority data nor its selector/path is serialized. A provisional
contract-profile verification may create the receipt before the final manifest
exists; the final signed manifest then binds that receipt by digest, avoiding a
self-referential hash.

`contextdb.release-publication-receipt/v1` records a public immutable HTTPS URI,
publication/retrieval timestamps, retrieved SHA-256 and exact artifact subject.
The final signed manifest and checksum set bind the receipt. The offline verifier
validates this chain but deliberately does not perform network retrieval; the
external publishing job owns that observation.

External evidence first enters the source workflow through the digest-pinned
receipt intake contract. Intake validates publication timestamps/public URI and
retrieved digest, install subject/platform/probe closure, operational drill
closure against the exact plan, old/new manifests and non-empty seed,
CycloneDX root hashes, and in-toto/SLSA subject/source bindings. It does
not establish that the submitting custodian is trustworthy or repeat the
external observation. That trust is added only when reviewed bytes enter a new
checksum closure and the final manifest/checksum subjects receive production
signatures from independently controlled keys.

Reproducibility is an explicit release goal. A manifest boolean does not prove it.
The proof needs at least two declared isolated builds whose normalized artifact
digests match, or a documented, reviewed variance explanation.
