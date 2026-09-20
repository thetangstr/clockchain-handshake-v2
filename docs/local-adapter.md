# clockchain-local-adapter

The pre-installed local half of the Clockchain agent handshake.

The hosted coordinator (`https://mcp.clockchain.network/handshake/mcp`, a
stateless streamable-HTTP MCP endpoint, no auth) issues `localAction` objects
inside tool responses. Each `localAction` carries helper steps — init, policy,
inspect, register, sign, verify-certificate — that must execute **locally**:
the session private key never leaves the machine and the server never signs.

The portable fallback asks the agent to download the pinned helper `.cjs` and
run a multi-KB `node --eval '<bootstrap>' …` command. Safety-conscious agent
runtimes correctly refuse runtime download-and-execute even though the bytes
are digest-pinned. The adapter removes that path: install it once, and every
local action becomes a single zero-input MCP tool call.

## Install

Claude Code / Claude Desktop:

```bash
claude mcp add clockchain-local-adapter -- npx -y @clockchain/local-adapter
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.clockchain-local-adapter]
command = "npx"
args = ["-y", "@clockchain/local-adapter"]
```

Generic MCP client configuration:

```json
{
  "mcpServers": {
    "clockchain-local-adapter": {
      "command": "npx",
      "args": ["-y", "@clockchain/local-adapter"]
    }
  }
}
```

From a checkout (or any unpacked copy of the package):

```bash
node <path>/index.mjs          # bundled package layout: assets/ beside index.mjs
node bin/clockchain-local-adapter.mjs   # repo layout
```

Requires Node 24.x. The asset directory can be overridden with
`CLOCKCHAIN_LOCAL_ADAPTER_ASSETS` (a directory containing `pin.json`,
`manifest.json`, and `clockchain-agent-handshake.cjs`), and the upstream
endpoint with `CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT` (used by tests).

## What it does

- **Proxies** `initialize`, `tools/list`, and `tools/call` to the hosted
  coordinator over streamable HTTP (plain JSON or SSE `event: message` frames).
  Upstream `result`/`error` payloads pass through verbatim; `tools/list` gets
  one extra tool appended.
- **Stages** each `helperStep`/`helperSteps` it observes in proxied tool
  responses, after validating: exact key set, the fixed `approvalTool`
  literal, `sha256(shellCommand)` and byte length, the verified prefix
  (`VERIFIED_HELPER_BOOTSTRAP` + the pinned `manifestDigest`), the strict
  `<op> --state-dir "${TMPDIR%/}/.clockchain/handshakes/<uuid>/<role>"` suffix
  grammar, operation/role/sessionId agreement between the fields and the
  suffix, the payload-required/payload-forbidden rule per operation, and the
  payload binds (local policy validation; signing-request and
  certificate-verification schema, `helperVersion`, role, sessionId, and the
  `externalBusinessActionPerformed === false` flag). Anything else fails
  closed with a generic refusal.
- **Executes** one staged step per `authorize_local_action` call: re-reads and
  re-verifies the pinned asset bytes at call time, creates the role state
  directory under the resolved `TMPDIR` with mode `0700`, spawns
  `node --input-type=commonjs --eval '<bootstrap>' <manifestDigest>
  <abs manifest> <abs helper> <op> --state-dir <abs dir>
  [--payload-base64url <enc>]` with a 120s bound, and returns the helper's
  validated `clockchain.agent-handshake-cli-result/v1` line. On helper
  failure only the stderr error code crosses the boundary.

## Trust model

- The private key is generated and used only inside the local helper; the
  coordinator never receives it and never signs.
- Integrity is a SHA-256 pin chain enforced twice: at startup
  (`pin.json` → manifest bytes → helper bytes, all under the exact release
  schema with canonical-byte equality) and again inside the spawned child by
  the verified bootstrap. A mismatch anywhere exits `86` /
  `ADAPTER_ASSET_VERIFICATION_FAILED` before serving or executing.
- The staged queue is FIFO, capped at 64 entries, and drops entries older than
  20 minutes at execution time. `authorize_local_action` takes zero arguments —
  no command, path, digest, or payload ever crosses the model boundary.
- Every refusal is the same generic
  `Clockchain local adapter refused the action.`; the adapter never reports
  which check failed.

## Why not the shellCommand fallback

The `shellCommand` text remains in responses for compatibility clients, but
with the adapter installed the model should never transcribe it: the staged
step it executes is the same digest-bound command, validated locally, with the
payload bytes taken from the validated envelope — not from model output.
