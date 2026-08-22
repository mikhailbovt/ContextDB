# Clean-install evidence

The PowerShell and POSIX wrappers run the standalone verifier against a copied
bundle in a newly created temporary directory. They do not install into a user
profile, overwrite an existing database, use a package registry, or invoke
Docker.

The default `release` profile is fail closed. It requires independently supplied
production Ed25519 public keys, passed roadmap proof closure, target-complete
artifacts, and runtime install receipts. Use the `contract` profile only for
contract fixtures; its output can never claim release readiness.

PowerShell:

```powershell
./deploy/release/clean-install.ps1 \
  -BundleRoot ./dist/contextdb-0.1.0-alpha.1 \
  -TrustedKey 'contextdb-release-2026=C:/trusted/contextdb-release-2026.pem' \
  -Report ./target/clean-install-windows-x86-64.json
```

POSIX shell:

```sh
./deploy/release/clean-install.sh \
  ./dist/contextdb-0.1.0-alpha.1 \
  release/artifact-manifest.json \
  release \
  ./target/clean-install-linux-x86-64.json \
  contextdb-release-2026=/trusted/contextdb-release-2026.pem
```

The minimal POSIX wrapper accepts one trusted key. Invoke the Python verifier
directly when a rotation bundle requires more than one independent key.

For native binary probes, the verifier injects one fresh
`CONTEXTDB_TOKEN_KEY_HEX` only into the isolated child environment. On Windows
it selects a different unpredictable `CONTEXTDB_STATE_HEAD_ID` for the source
and clone-import destinations; `CONTEXTDB_TOKEN_KEY_FILE` and
`CONTEXTDB_STATE_HEAD_FILE` are absent. On Unix it selects two owner-only state
head files in a temporary authority directory outside the copied bundle and
archive directory; `CONTEXTDB_STATE_HEAD_ID` is absent. The verifier never
records the key, authority ID, authority path, or authority contents and fails
if key/state-head sidecar material appears beside an archive.

The temporary Unix authority directory is removed in a `finally` path. On
Windows the verifier derives the exact HKCU subkeys from its two private IDs
with the same BLAKE3 rule as the CLI and deletes only those exact keys and lock
files in `finally`, including after a failed probe. It never deletes the
`StateHeads` parent or enumerates unrelated authorities. Cleanup failure is a
failed receipt probe, not a warning.

Production packages still require independent key and state-head custody,
backup/rotation or lifecycle procedures, target-platform receipts, and proof
that the authority custodian itself cannot be rolled back; this probe is not
that proof.

The resulting JSON is a host-specific receipt. It does not substitute for the
required Linux x86_64, Linux arm64, and macOS arm64 receipts, nor for external
publication evidence. The receipt includes a UTC generation timestamp, exact
non-secret argv, hashed stdout/stderr, and rejects a binary whose reported
version differs from the release manifest.

## Upgrade, rollback, and disaster recovery

`operational-drill.ps1` and `operational-drill.sh` wrap the same fail-closed
Python runner for an exact old/new bundle pair. The plan is validated against
`contextdb.release-operational-plan/v1` and pins each artifact manifest digest,
version and host binary ID, plus a non-empty portable seed and minimum commit
sequence. The new SemVer precedence must be strictly greater. Both bundles are
copied to disposable directories before verification or execution.

PowerShell:

```powershell
./deploy/release/operational-drill.ps1 `
  -OldBundleRoot ./dist/contextdb-0.1.0-alpha.1 `
  -NewBundleRoot ./dist/contextdb-0.1.0-beta.1 `
  -Plan ./target/windows-operational-plan.json `
  -TrustedKey 'contextdb-release-2026=C:/trusted/contextdb-release-2026.pem' `
  -Report ./target/windows-operational-receipt.json
```

POSIX:

```sh
./deploy/release/operational-drill.sh \
  ./dist/contextdb-0.1.0-alpha.1 \
  ./dist/contextdb-0.1.0-beta.1 \
  ./target/linux-operational-plan.json \
  release \
  ./target/linux-operational-receipt.json \
  contextdb-release-2026=/trusted/contextdb-release-2026.pem
```

The drill creates a disposable activation marker and exercises old
seed-import/status/doctor/export, new clone-import/doctor, candidate activation, explicit
rollback to the untouched old database with a byte-identical logical export,
and a separate DR export/import/doctor/activation. Old, candidate and recovered
destinations use separate state-head authorities. No real supervisor is
changed, `--force` is never used, and the receipt always has
`release_ready: false`. Once the plan and bundles pass input validation, a
runtime probe failure still produces a schema-valid failed receipt and a
non-zero exit so the partial drill is diagnosable without being accepted. The
runner invokes no network command but does not claim OS-level network isolation.
