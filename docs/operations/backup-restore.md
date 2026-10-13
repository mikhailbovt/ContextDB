# Backup, restore, and portable export

## Current logical archive workflow

Create a verified copy without overwriting the live database:

```text
contextdb --json doctor ./state/contextdb.ctxb
contextdb --json export ./state/contextdb.ctxb ./backup/contextdb.logical.v1.ctxb
# select a new empty destination authority before import
contextdb --json import ./restore/contextdb.ctxb ./backup/contextdb.logical.v1.ctxb
contextdb --json doctor ./restore/contextdb.ctxb
```

All commands require exactly one external token-key source and one independently
protected state-head authority. Import never creates or persists a key. Restore
the intended protected key through
`CONTEXTDB_TOKEN_KEY_HEX` or `CONTEXTDB_TOKEN_KEY_FILE` (normally the original
key for token continuity); a key change is a separate reviewed rotation, not an
implicit side effect of import. On Windows select a fresh HKCU authority ID with
`CONTEXTDB_STATE_HEAD_ID`; on Unix select a fresh protected external
`CONTEXTDB_STATE_HEAD_FILE`. Raw logical import is clone-only: it refuses an
existing archive or authority and `--force` is disabled. Recovery builds a fresh
isolated path, verifies it, and switches the deployment only through an explicit
operator action.

The authenticated workspace operations `export_archive` and `import_archive`
remain unavailable. The production lifecycle service also leaves
`create_backup` and `restore_backup` unavailable: a workspace-scoped caller
cannot be treated as database-global authority. Those methods authenticate
first and return typed `Unsupported` results. Subject-safe transfer needs a
complete filtered closure and is not implemented by the operator formats below.

## Restricted local Codex composite recovery

The local Codex hybrid profile has a separate host-only recovery path. It is
reachable only as the `codex-backup` and `codex-restore` CLI commands; neither
command is registered as an MCP tool or routed by `contextdb api`. The CLI
loads the externally anchored lifecycle state, derives one fixed local Admin
authority from the protected token-key source, and authenticates before reading
either authority or an untrusted backup file.

Quiesce every Codex MCP owner using the state before either command. On Windows,
load the plugin's exact token key and state-head selector, then run
`contextdb mcp-broker-stop <state>`; a successful return includes an
authenticated shutdown acknowledgement and proof that the exact state-head
lock was released. Linux uses the same authenticated single-owner broker and
stop command with its exact external file selectors. See
[Local MCP broker](local-mcp-broker.md). Then create a new bounded
canonical envelope without overwriting an existing file:

```text
contextdb --json codex-backup ./state/codex-memory.ctxb ./backup/codex-memory.cdb-backup
```

The plaintext envelope format is `contextdb.codex-composite-backup.v1`. It contains the
verified canonical lifecycle archive and all native Fjall logical keyspaces,
with exact component formats, commit sequences, database identity, BLAKE3
digests, a canonical footer, and finite 512 MiB lifecycle / 256 MiB native
component caps. It does **not** contain the token key, external state-head
authority, production Fjall runtime ledger, signatures, or KMS custody. The CLI
prints only a content-free receipt; the backup bytes are written to the explicit
destination with no-clobber atomic installation.

An explicitly provisioned encrypted native profile uses
`contextdb.codex-composite-backup.v2`, containing the native v3 ciphertext archive
and exact database, custody and suppression authority identities. The lifecycle
component remains plaintext. Neither format contains master/token keys, wrapped
key catalogs, host profile paths or authority snapshots. Restore requires the
current retained profile and authorities; a backup cannot configure or replace
them. Plaintext and encrypted envelopes cannot be interchanged implicitly.

Restore is intentionally not a live replacement API. The lifecycle archive and
database identity must still match the backup byte-for-byte, and the native
`<state>.native-fjall` target must be pristine. Preserve the old sidecar instead
of deleting it, then restore:

```powershell
$dataRoot = Join-Path $env:LOCALAPPDATA 'ContextDB\Codex\contextdb-memory'
$config = Get-Content -LiteralPath (Join-Path $dataRoot 'config\contextdb-memory.json') -Raw |
  ConvertFrom-Json
$state = [IO.Path]::GetFullPath([string]$config.archive_path)
$contextdb = [IO.Path]::GetFullPath([string]$config.contextdb_exe)
$backup = Join-Path $env:USERPROFILE 'ContextDB-Backups\codex-memory.cdb-backup'
$native = "$state.native-fjall"
Move-Item -LiteralPath $native -Destination "$native.pre-restore"
& $contextdb --json codex-restore $state $backup
```

For that stable custody root, load `CONTEXTDB_TOKEN_KEY_HEX` from its
DPAPI-protected secret and set `CONTEXTDB_STATE_HEAD_ID` from the config loaded
above exactly as the trusted launcher does; never copy either value into the
backup or a script argument.
Choose a unique quarantine suffix if `.pre-restore` already exists. Format,
digest, footer, database-identity, lifecycle-match, logical-integrity, and
non-pristine-target validation all finish before the replacement transaction
starts. The native replacement is one synchronized Fjall transaction and is
deep-verified before acknowledgement. A storage failure during commit or that
post-commit verification produces no success receipt, but the new sidecar must
then be treated as quarantined rather than assumed pristine. Keep the original
quarantined authority until restart and semantic-recall checks are complete;
run `doctor` separately for the lifecycle archive because it is not a
native-memory verification command.

This restricted envelope closes local semantic-memory restart recovery only. A
full quiesced operator disaster-recovery set is still required for lifecycle
runtime-ledger and external-authority recovery; there is no live production
restore executor.

Record the source binary/version manifest, archive size, SHA-256 distribution
digest, BLAKE3 logical digest, commit sequence, destination doctor receipt, and
operator/trace ID. Store receipts separately from sensitive content.

## Explicit encrypted native provisioning

With all MCP owners stopped, select the existing authenticated lifecycle archive,
token key and external state-head authority. Supply a separate nonzero 32-byte
master key through `CONTEXTDB_NATIVE_MASTER_KEY_HEX` from protected host custody;
it must differ from the token key. Keep keys out of command arguments and logs.
The custody destination must be new, absolute, unlinked and outside the database
directory tree:

```text
contextdb --json codex-native-init D:/ContextDB/data/memory.ctxb --custody-root D:/ContextDB-custody/native-memory
```

The command refuses an existing native sidecar, profile or custody destination.
It retains a signed `<state>.native-profile.json` descriptor, pins its immutable
digest in the external state head, then creates `<state>.native-fjall` and the
independent `keys/` and `suppression/` authorities. Their exact identities and
formats are verified before activation. Ordinary lifecycle publications and
recovery preserve the pin. Interrupted provisioning retains its descriptor and
fails closed; automatic completion or reseeding is not implemented.

Every later native CLI/MCP opening requires the same master, profile and retained
authorities. A proxy validates its selection before joining a running broker;
the authenticated handshake and acknowledgement bind the profile digest.
Reference mode cannot bypass it. Losing both local native state and the profile
still leaves the external pin, so startup refuses plaintext. Token-authorized
`mcp-broker-stop` can quiesce an owner without the missing master/profile, but
cannot read native bytes or start an owner.

Encrypted native restore may create a missing pristine sidecar only after the
complete envelope, exact lifecycle archive and retained custody match. Before
creating that target, restore retains a signed local pending state and an external
state-head fence. Only successful restore and deep verification clear the fence;
failed or interrupted restore stays closed even if an older signed Ready profile
is replayed. Explicit interrupted restore recovery is not yet implemented. Restore
never creates replacement key or suppression authorities. Lifecycle-only export remains
separate; `custody-snapshot-export` refuses this native pin even when local native
files are missing. Existing plaintext stores require explicit migration, which
is not yet implemented. This opt-in does not encrypt the lifecycle composition
or complete global deletion/admission.

## Evidence boundary

The CLI export is a canonical logical archive. It is useful for portability and
clean-install examples, but it is not the complete RFC 25.31/M16 backup gate:

- it is not the published encrypted backup envelope;
- it does not prove snapshot behavior under concurrent writers;
- it does not carry production signatures/key custody;
- it does not contain or back up the independently managed token key;
- it does not contain the independently managed anti-rollback state-head
  authority;
- it does not prove incremental or primary-only modes;
- it does not verify every primary/derived index, delete/tombstone, provider,
  export and retained-backup disposition;
- it has not passed required-platform fault injection or disaster recovery.

Do not label a logical export as an encrypted backup. Before Beta, backup/restore
must exercise signature/checksum verification, feature compatibility, temporary
restore, journal replay, invariants, missing-index rebuild and atomic activation
as required by RFC 25.32.

## Full production-store checkpoint boundary

The Fjall adapter deliberately returns `Unsupported` for an online physical
checkpoint. `create_backup` therefore does not copy an open database and call
the result consistent. A complete production recovery set can currently be
captured only while every writer and daemon is stopped, after a successful
`doctor`/production verification and external-head reconciliation. The set is:

- the canonical `<database>.ctxb` archive;
- the closed `<database>.ctxb.fjall` directory as one filesystem snapshot;
- the matching external state-head authority snapshot;
- the exact binary/version/format manifest and hashes;
- a reference to the separately escrowed token key, never the key inside the
  backup bundle.

All members must come from the same quiesced point. Hash the archive and every
physical file, then hash a sorted manifest of those hashes. Copying only the
archive loses stream/runtime/durable-ledger state. Copying only Fjall loses the
canonical archive and authority binding. Copying the authority at another time
can produce a rollback-divergent set that correctly fails closed.

The authority is bound to the canonical database path. A physical recovery set
is therefore for disaster recovery at that same protected path (or an isolated
host with the same path mapping and restored authority), not a general clone
format. Side-by-side clones continue to use the logical export/import workflow
and a fresh authority. There is no live full-store restore or automatic atomic
activation executor yet.
