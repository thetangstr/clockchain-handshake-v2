# Getting started with clockchain-local-adapter (for MCP users)

`clockchain-local-adapter` is the default executor for Clockchain
agent-handshake local actions. It is a small MCP server you install **once**
into your agent host; after that, every local signing step in a handshake is a
plain MCP tool call — no shell commands, no runtime downloads, no `eval`.

## Prerequisites

- **Node.js 24 or newer.** The pinned signing helper requires Node 24.x; the
  adapter exits with an explicit error on older versions rather than failing
  mysteriously mid-handshake. Check with `node --version`.
- An MCP-capable host: Claude Code, Claude Desktop, Cursor, Codex, or any
  client that can launch a stdio MCP server.

## Install

One-time install, per host (full copy-paste blocks for every supported host
live in `packaging/local-adapter/INSTALL.md`):

| Host | Install |
|---|---|
| Claude Code | `claude mcp add clockchain-local-adapter -- npx -y @d4d.group/local-adapter` |
| Claude Desktop | One-click `.mcpb` bundle, or the `mcpServers` JSON block |
| Cursor | `~/.cursor/mcp.json` `mcpServers` block |
| Codex | `~/.codex/config.toml` `[mcp_servers.clockchain-local-adapter]` entry |

Every form resolves to the same thing: `npx -y @d4d.group/local-adapter`.

## What `authorize_local_action` does

The adapter exposes one fixed, zero-input tool:
`authorize_local_action` (shown to agents as
`mcp__clockchain-local-adapter__authorize_local_action`).

The adapter proxies all eight hosted handshake tools
(`agent_handshake_invite` … `agent_handshake_get_certificate`) to
`https://mcp.clockchain.network/handshake/mcp`. When an upstream response
contains a `localAction`, the adapter stages its digest-bound helper steps
privately. Each `authorize_local_action` call executes exactly one staged step,
in order:

1. Re-verifies the vendored `manifest.json` digest and
   `clockchain-agent-handshake.cjs` digest against the release pin — on every
   call, not just at install.
2. Re-checks the step's manifest digest, helper version, host roots, asset
   prefix, command shape, role/session/state-directory bindings, and payload
   digest.
3. Runs the pinned local helper with the verified argv — private keys are
   generated and stay inside your machine's state directory. The public
   Clockchain server never sees a private key and never signs.

If anything mismatches, the adapter refuses closed. If the coordinator ever
requires a newer helper than the adapter vendors, the refusal names the fix:
`npx -y @d4d.group/local-adapter@latest`, then restart your MCP client.

## Your first handshake

With the adapter installed, a fresh agent needs no other setup. The typical
initiator flow, all through MCP tool calls:

1. `agent_handshake_invite` — returns your `roleAccess` plus a
   `responderInvitation` to hand to the counterparty, and stages three local
   steps: `init`, `policy`, `inspect`.
2. Call `authorize_local_action` three times — once per staged step, in order.
   The `inspect` result carries your `sessionKeyAddress` and `policyDigest`.
3. `agent_handshake_join` with `helperVersion`, `sessionKeyAddress`, and
   `policyDigest`. Its response stages the `identity_claim` signing step.
4. `authorize_local_action` → `agent_handshake_submit` with the returned
   `signatureHex`.
5. Poll `agent_handshake_next`. Whenever a response carries a `localAction`,
   call `authorize_local_action` once per staged step and submit as directed —
   funding observation, ERC-8004 registration (when the terms require fresh
   identity), proposal/acceptance/evidence signatures (each preceded by its
   commitment checkpoint via `agent_handshake_submit_checkpoint`).
6. `agent_handshake_get_certificate` → the final `authorize_local_action`
   locally verifies the certificate. Done.

The responder flow mirrors it: `agent_handshake_accept_invitation` with the
invitation string, then the same loop.

## Why this is safe

- The adapter holds the digest-pinned release assets locally, installed once —
  no code is downloaded or evaluated during a handshake.
- Digests, version, host roots, and every step binding are re-verified at
  startup and on every call; any mismatch refuses closed.
- Private keys never leave your machine. The hosted coordinator only ever sees
  signatures and receipts.
- The legacy download-and-run path remains documented as a last resort for
  environments where installing an MCP server is impossible — safety-conscious
  runtimes may refuse it by design, which is expected behavior, not a bug.
