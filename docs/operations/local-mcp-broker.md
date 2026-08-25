# Local MCP broker on Linux and Windows

`contextdb mcp` uses a single-owner authenticated local broker on both supported
platforms so independent Codex tasks can share one ContextDB archive without
weakening either durable lock. The broker is the only process that opens the
external `StateHeadStore` transaction lock and the native Fjall sidecar. Each
short-lived MCP process remains a stdio proxy and never opens either store.

Both transports are local only and derive endpoint identity from the canonical
archive path:

- Windows uses a local named pipe and rejects remote clients.
- Linux uses an owner-only Unix-domain socket inside an owner-only directory
  derived from the external state-head authority location. The socket is kept
  outside the archive directory, rejects symbolic links and foreign ownership,
  enforces mode `0600`, and refuses overlong platform socket paths.

Neither transport binds TCP, HTTP, gRPC, or any other network listener.

## Startup and request ordering

The first `contextdb mcp <archive> ...` proxy tries the deterministic local
endpoint. If no owner exists, it launches one detached broker with the exact
external token-key and state-head authorities already selected for the archive.

On Windows, startup passes through a short-lived non-interactive PowerShell
launcher. Its constant script receives trusted paths through task-specific
environment variables, uses `Start-Process -WindowStyle Hidden`, removes the
temporary launcher variables before broker startup, and exits after the detached
start operation completes.

On Linux, the executable starts its hidden broker command with stdio detached.
It inherits only the existing file-based custody selectors needed to reopen the
same archive. The owner-only endpoint directory must already remain outside the
archive directory; a stale owned socket is removed only after failed connection
and strict socket/ownership checks.

The extra Windows launcher boundary is intentional. Directly spawning a
persistent grandchild from an MCP proxy can inherit captured stdout/stderr
handles, causing Codex to wait forever for EOF. The short-lived launcher breaks
that handle custody, and the proxy waits for its exit code before connecting.
Linux instead detaches all three standard streams directly.

The broker claims its first named-pipe instance or Unix socket before opening
durable stores. Concurrent auto-start attempts therefore select one owner
without weakening the state-head or Fjall locks. A later proxy can reopen a
cleanly stopped or crashed owner only after the endpoint identity and normal
authenticated archive/storage custody checks succeed.

Each connection has its own fixed MCP authority and trace cache. A global FIFO
request gate serializes JSON-RPC decode and service execution across all
connections, so concurrent mutations have one durable commit order. Requests
remain newline-delimited and bounded by the MCP 16 MiB frame cap. Broker
handshakes are capped at 64 KiB and acknowledgements at 4 KiB.

## Local mutual authentication

The proxy loads the existing external token key only to authenticate the local
session; it does not acquire a state or Fjall lock. Its bounded handshake binds
the canonical local endpoint identity, broker mode, random nonce, and fixed MCP authority
with a domain-separated keyed BLAKE3 MAC. The broker verifies that MAC before
constructing an `McpServer`.

The broker's acknowledgement uses a different MAC domain and binds the accept
decision, handshake nonce, endpoint identity, operation, reference/production mode,
schema version, and broker process ID. A proxy does not forward any model MCP
frame until that acknowledgement verifies. This prevents a local pipe squatter
without the token key from impersonating a named-pipe or Unix-socket broker and
consuming the subsequent MCP stream.

The broker rejects duplicate authenticated nonces with a FIFO/set cache capped
at 4,096 entries. That replay cache is deliberately process-local and bounded;
durable cross-restart replay custody is not claimed by this local development
transport.

## Quiescence, backup, and binary updates

While either native broker is running, direct operator commands cannot open the
same exclusive authorities. First prevent the host from launching new MCP
proxies, then quiesce the broker before backup, restore, archive inspection,
migration, or replacing the executable:

```powershell
$dataRoot = Join-Path $env:LOCALAPPDATA 'ContextDB\Codex\contextdb-memory'
$config = Get-Content -LiteralPath (Join-Path $dataRoot 'config\contextdb-memory.json') -Raw |
  ConvertFrom-Json
& ([string]$config.contextdb_exe) mcp-broker-stop ([string]$config.archive_path)
```

On Windows, load the exact `CONTEXTDB_TOKEN_KEY_HEX` and
`CONTEXTDB_STATE_HEAD_ID` used by the plugin before this command.

On Linux, select the same owner-only external files used by the installed host:

```sh
export CONTEXTDB_TOKEN_KEY_FILE=/absolute/external/secrets/token-key.local
export CONTEXTDB_STATE_HEAD_FILE=/absolute/external/authority/state-head.json
contextdb mcp-broker-stop /absolute/archive/memory.ctxb
```

Do not set `CONTEXTDB_TOKEN_KEY_HEX` alongside `CONTEXTDB_TOKEN_KEY_FILE`, and do
not use the Windows-only `CONTEXTDB_STATE_HEAD_ID` on Linux. The file contents
and token material must never be copied into the database directory or logs.

On both platforms, the stop request is authenticated and receives
a signed acknowledgement. The command then waits until it can acquire and
release the exact state-head lock. Exit code 0 therefore means the broker was
already absent or both durable authorities have been dropped. Authentication,
acknowledgement, startup-deadline, or quiescence failure exits nonzero.

After a successful stop, operator work may open the state. The next
`contextdb mcp` invocation starts a broker from the currently selected
executable, which is also how a local binary update becomes active. Replacing a
binary on disk without first stopping the old broker does not migrate the
already running process.

## Support boundary

The authenticated broker is included in the native Linux x86_64 and Windows
x86_64 local-MCP developer-preview packages. A Unix-domain socket is local IPC,
not a public MCP endpoint or network service. Linux arm64, macOS, signed
service installation, hostile-local-user isolation, and production hard-delete
guarantees are outside the verified preview support boundary.
