# Installing clockchain-local-adapter

`@d4d.group/local-adapter` is a stdio MCP server. Your MCP host launches it as
a local child process; it proxies the hosted Clockchain handshake tools and
executes each staged, digest-bound local action through the pinned local
helper. Install it once and every local action becomes a single zero-input tool
call (`authorize_local_action`) instead of a download-and-execute fallback.

> **Prerequisite: Node.js 24 or newer** must be installed and on `PATH` (every
> snippet below launches the adapter via `npx`/`node`). Check with
> `node --version` — the pinned helper refuses to run under older majors.

> **Coordinator endpoint:** while the ACM4 demo pin is live, the hosted edge
> serves the current build's handshake surface at
> `https://mcp.clockchain.network/next/handshake/mcp` (`/handshake/mcp` itself
> is pinned to a frozen 2.1.6 demo instance). Set
> `CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT` to the `/next` URL as shown in each
> snippet below — published packages prior to this note default to the pinned
> URL.

## Why this is safe

The adapter holds digest-pinned release assets — `pin.json`, `manifest.json`,
and the `clockchain-agent-handshake.cjs` helper — installed once at install
time and shipped inside the package, so nothing executable is ever fetched at
runtime. It re-verifies the full pin chain (manifest digest + helper digest +
version + host roots) at startup and again on every tool call, and the spawned
helper bootstrap re-checks both digests inside the child process. Your session
private key is generated and used only inside that local helper — keys never
leave the machine and the public coordinator never signs. Any mismatch, at any
gate, refuses closed with a generic error before anything executes.

## Claude Code CLI

Registers the server in your Claude Code MCP configuration so every session
can reach the handshake tools plus `authorize_local_action`.

```bash
claude mcp add clockchain-local-adapter \
  -e CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT=https://mcp.clockchain.network/next/handshake/mcp \
  -- npx -y @d4d.group/local-adapter
```

Verify: `claude mcp list` shows `clockchain-local-adapter`. Inside a session,
`tools/list` (or `/mcp`) should expose
`mcp__clockchain-local-adapter__authorize_local_action`.

## Claude Desktop

Merge this block into the `mcpServers` object in
`claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "clockchain-local-adapter": {
      "command": "npx",
      "args": ["-y", "@d4d.group/local-adapter"],
      "env": {
        "CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT": "https://mcp.clockchain.network/next/handshake/mcp"
      }
    }
  }
}
```

No config editing alternative: install `dist/clockchain-local-adapter.mcpb`
(the DXT bundle produced by `node scripts/build-local-adapter-mcpb.mjs`) by
double-clicking it or via Claude Desktop → Settings → Extensions. It runs the
same pinned bytes from `server/` inside the bundle.

Verify: restart Claude Desktop, then Settings → Developer shows
`clockchain-local-adapter` running; its tool list includes
`authorize_local_action`.

## Cursor

Add the server to `~/.cursor/mcp.json` (global) or a project's
`.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "clockchain-local-adapter": {
      "command": "npx",
      "args": ["-y", "@d4d.group/local-adapter"],
      "env": {
        "CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT": "https://mcp.clockchain.network/next/handshake/mcp"
      }
    }
  }
}
```

Verify: Cursor Settings → MCP shows `clockchain-local-adapter` with a green
status; the tool list includes `authorize_local_action` (plus the proxied
`agent_handshake_*` tools when the coordinator is reachable).

## Codex

Add an `[mcp_servers.*]` table to `~/.codex/config.toml` (Codex's MCP server
registry):

```toml
[mcp_servers.clockchain-local-adapter]
command = "npx"
args = ["-y", "@d4d.group/local-adapter"]
env = { CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT = "https://mcp.clockchain.network/next/handshake/mcp" }
```

Verify: `codex mcp list` shows `clockchain-local-adapter`; a `tools/list`
against it includes `authorize_local_action`.

## Generic MCP host

Any host that speaks stdio MCP can launch the adapter with:

```json
{
  "command": "npx",
  "args": ["-y", "@d4d.group/local-adapter"],
  "env": {
    "CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT": "https://mcp.clockchain.network/next/handshake/mcp"
  }
}
```

(or `node /path/to/index.mjs` for an unpacked package — `assets/` must sit
beside `index.mjs`).

Verify: send `initialize` then `tools/list` on the stdio JSON-RPC stream; the
response lists `authorize_local_action` even when the upstream coordinator is
unreachable. Environment overrides: `CLOCKCHAIN_LOCAL_ADAPTER_ASSETS`
(alternate pinned-asset directory) and `CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT`
(upstream coordinator URL, must be `https://`).

## Troubleshooting

- Server exits immediately with code 86 / `ADAPTER_ASSET_VERIFICATION_FAILED`:
  the pinned assets failed verification — reinstall the package rather than
  editing files under `assets/`.
- `clockchain-local-adapter requires Node 24.x` warning: upgrade Node; the
  helper will refuse to execute under other majors.
