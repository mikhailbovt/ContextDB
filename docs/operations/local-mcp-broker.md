# Local MCP broker on Windows

`contextdb mcp` uses a single-owner local broker on Windows so independent
Codex tasks can share one ContextDB archive without weakening either durable
lock. The broker is the only process that opens the external `StateHeadStore`
transaction lock and the native Fjall sidecar. Each short-lived MCP process is
a stdio proxy and never opens either store.

This is a local transport only. The endpoint is a Windows named pipe derived
from the digest of the canonical archive path. It rejects remote clients and
does not bind TCP, HTTP, or another network listener.

## Startup and request ordering

The first `contextdb mcp <archive> ...` proxy tries the deterministic named
pipe. If no owner exists, it runs a short-lived, non-interactive Windows
PowerShell launcher with a constant script and trusted path values supplied in
task-specific environment variables. The launcher uses
`Start-Process -WindowStyle Hidden`, waits until the detached start operation
has completed, and exits. The temporary launcher variables are removed before
the broker child starts. The broker necessarily retains the already selected
ContextDB token-key source and state-head selector because it owns those
authorities.

The extra launcher boundary is intentional. Directly spawning a persistent
grandchild from an MCP proxy can inherit the proxy's captured stdout/stderr
handles on Windows. Codex would then wait forever for EOF after the proxy had
exited. The short-lived launcher breaks that handle custody, and the proxy waits
for its exit code before connecting.

The broker claims the first named-pipe instance before opening the durable
stores. Concurrent auto-start attempts therefore select one owner without
contending on the state-head or Fjall locks. A stale endpoint disappears with a
crashed broker; a later proxy starts a new owner, which performs the normal
authenticated archive and storage reopen checks.

Each connection has its own fixed MCP authority and trace cache. A global FIFO
request gate serializes JSON-RPC decode and service execution across all
connections, so concurrent mutations have one durable commit order. Requests
remain newline-delimited and bounded by the MCP 16 MiB frame cap. Broker
handshakes are capped at 64 KiB and acknowledgements at 4 KiB.

## Local mutual authentication

The proxy loads the existing external token key only to authenticate the local
session; it does not acquire a state or Fjall lock. Its bounded handshake binds
the canonical pipe identity, broker mode, random nonce, and fixed MCP authority
with a domain-separated keyed BLAKE3 MAC. The broker verifies that MAC before
constructing an `McpServer`.

The broker's acknowledgement uses a different MAC domain and binds the accept
decision, handshake nonce, pipe identity, operation, reference/production mode,
schema version, and broker process ID. A proxy does not forward any model MCP
frame until that acknowledgement verifies. This prevents a local pipe squatter
without the token key from impersonating a broker and consuming the subsequent
MCP stream.

The broker rejects duplicate authenticated nonces with a FIFO/set cache capped
at 4,096 entries. That replay cache is deliberately process-local and bounded;
durable cross-restart replay custody is not claimed by this local development
transport.

## Quiescence, backup, and binary updates

While the Windows broker is running, direct operator commands cannot open the
same exclusive authorities. First prevent the host from launching new MCP
proxies, then quiesce the broker before backup, restore, archive inspection,
migration, or replacing the executable:

```powershell
$dataRoot = Join-Path $env:LOCALAPPDATA 'ContextDB\Codex\contextdb-memory'
$config = Get-Content -LiteralPath (Join-Path $dataRoot 'config\contextdb-memory.json') -Raw |
  ConvertFrom-Json
& ([string]$config.contextdb_exe) mcp-broker-stop ([string]$config.archive_path)
```

Load the exact `CONTEXTDB_TOKEN_KEY_HEX` and `CONTEXTDB_STATE_HEAD_ID` used by
the plugin before this command. The stop request is authenticated and receives
a signed acknowledgement. The command then waits until it can acquire and
release the exact state-head lock. Exit code 0 therefore means the broker was
already absent or both durable authorities have been dropped. Authentication,
acknowledgement, startup-deadline, or quiescence failure exits nonzero.

After a successful stop, operator work may open the state. The next
`contextdb mcp` invocation starts a broker from the currently selected
executable, which is also how a local binary update becomes active. Replacing a
binary on disk without first stopping the old broker does not migrate the
already running process.

## Non-Windows behavior

The broker is currently Windows-only. On non-Windows targets,
`contextdb mcp` retains the direct stdio path: that process opens the archive
and selected storage itself and holds the exclusive authorities for its
lifetime. Concurrent MCP processes against one archive are therefore not
supported there; the host must serialize them and stop every direct MCP process
before operator work. No cross-platform broker or signed service installation
is claimed by this slice.
