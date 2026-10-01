# clockchain-local-adapter

The pre-installed local half of the Clockchain agent handshake.

The hosted coordinator (`https://mcp.clockchain.network/next/handshake/mcp`, a
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

> **Prerequisite: Node.js >= 24.** The adapter enforces this at startup —
> on an older runtime it prints an actionable error to stderr and exits
> before serving a single message. Install Node 24+ from
> <https://nodejs.org> or via your version manager (nvm/fnm/volta), then
> restart your MCP client.

Claude Code / Claude Desktop:

```bash
claude mcp add clockchain-local-adapter -- npx -y @d4d.group/local-adapter
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.clockchain-local-adapter]
command = "npx"
args = ["-y", "@d4d.group/local-adapter"]
```

Generic MCP client configuration:

```json
{
  "mcpServers": {
    "clockchain-local-adapter": {
      "command": "npx",
      "args": ["-y", "@d4d.group/local-adapter"]
    }
  }
}
```

From a checkout (or any unpacked copy of the package):

```bash
node <path>/index.mjs          # bundled package layout: assets/ beside index.mjs
node bin/clockchain-local-adapter.mjs   # repo layout
```

Requires Node 24.x (the pinned helper refuses under any other major — see
the prerequisite above). The asset directory can be overridden with
`CLOCKCHAIN_LOCAL_ADAPTER_ASSETS` (a directory containing `pin.json`,
`manifest.json`, and `clockchain-agent-handshake.cjs`), the upstream
endpoint with `CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT` (used by tests), and the
Node executable that runs the pinned helper with
`CLOCKCHAIN_LOCAL_ADAPTER_NODE` (defaults to `process.execPath`; needed
only for single-file compiled builds, where `process.execPath` is the
adapter binary itself).

## Upgrading

The adapter vendors one pinned helper release. When the coordinator moves
to a newer release, a staged step minted against it fails validation and the
adapter refuses with an upgrade-directed message instead of the generic
refusal:

> `clockchain-local-adapter is behind the coordinator's required helper
> release — upgrade with: npx -y @d4d.group/local-adapter@latest, then
> restart your MCP client. …`

Upgrade with:

```bash
npx -y @d4d.group/local-adapter@latest
```

then restart your MCP client. If the adapter is already current and you
still see that message, the step is pinned to a different release — a
mismatch that must not be bypassed.

## Single-file binaries (experimental)

`npm run local-adapter:bin:build` (or
`node scripts/build-local-adapter-binaries.mjs [target …]`) compiles the
verified npm bundle into a standalone executable via `bun build --compile`
into `dist/bin-local-adapter/`, alongside a shared `assets/` directory that
must ship beside the binary — the adapter resolves `assets/` relative to
its own executable path (and `CLOCKCHAIN_LOCAL_ADAPTER_ASSETS` still wins).
Proxying and staging work fully; `authorize_local_action` still requires a
real Node >=24 for the pinned helper spawn, pointed at via
`CLOCKCHAIN_LOCAL_ADAPTER_NODE`.

## What it does

- **Proxies** `initialize`, `tools/list`, and `tools/call` to the hosted
  coordinator over streamable HTTP (plain JSON or SSE `event: message` frames).
  Upstream `result`/`error` payloads pass through verbatim; `tools/list` gets
  the two local tools appended (`authorize_local_action`,
  `sign_agent_contract_bind`).
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
- **Signs one agent-contract bind statement** per `sign_agent_contract_bind`
  call (since 2.1.10) — see below. Never proxied upstream.

## Trust model

- The private key is generated by the local helper and used only on this
  machine: by the helper for protocol signing, and (since 2.1.10) by the
  adapter process itself, through the same wallet-bridge reader, for the one
  `agent-contract.bind/v1` statement described below. The coordinator never
  receives it and never signs; no tool response ever carries it.
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
  which check failed. The single exception is a structurally valid step
  pinned to a different release digest, which gets the upgrade-directed
  refusal described in Upgrading — still fail-closed, but actionable.

## Contract bind statements (`sign_agent_contract_bind`, 2.1.10)

The agent-contract server (`/contract/mcp`) late-binds a `*` bearer token to
a handshake party only with proof that the caller holds that party's
handshake session key — the secp256k1 wallet the pinned helper created at
`${TMPDIR}/.clockchain/handshakes/<sessionId>/<role>/wallet.json`, whose
address the certificate carries as `result.parties[side].sessionKeyAddress`.
Only this adapter's uid can read that wallet, so the adapter produces the
proof:

```text
contract_bind_challenge            -> { challenge, expiresAt }      (contract server)
sign_agent_contract_bind(statement) -> { statement, signature, sessionKeyAddress }   (this adapter)
contract_bind({ ..., bindStatement: statement, bindStatementSignature: signature })   (contract server, inside the challenge TTL, default 60 s)
```

Input is exactly the server's seven-key statement:

```json
{ "domain": "agent-contract.bind/v1", "runId": "<handshake sessionId>",
  "side": "initiator|responder", "tokenKeyId": "<contract token keyId>",
  "serverKeyId": "<contract server signer keyId>",
  "challenge": "<64 lowercase hex>", "issuedAt": "<ISO-8601 UTC, Z>" }
```

The adapter signs `sha256(canonicalJson(statement))` (a byte-for-byte port of
the server's `canonical.ts`, held to the server's own vectors) as an EIP-191
`personal_sign` over the raw 32-byte digest, self-checks the result (v 27/28,
low-s, recovers to the wallet) and returns the canonical statement echo, the
signature and the lowercase session address. Refusals carry one fixed code
and never echo input: `BIND_ARGUMENTS_INVALID`, `BIND_NOT_CONFIGURED`, `BIND_KEY_ID_NOT_ALLOWED`,
`BIND_ISSUED_AT_OUT_OF_WINDOW` (older than 120 s or more than 30 s ahead of
the adapter clock), `BIND_SESSION_NOT_HELD`, `BIND_SESSION_NOT_VERIFIED`,
`BIND_SESSION_EXPIRED`, `BIND_SIGNING_FAILED`.

### Verified sessions and the session deadline

The tool signs only for a session whose certificate this adapter saw
verified. When a role's terminal `verify-certificate` step succeeds through
`authorize_local_action` with `certificateVerified: true` / `VERIFIED`, the
adapter writes `contract-bind-session.json` (create-only, 0600) beside
`wallet.json`: the sessionId, role, the party `sessionKeyAddress` the
certificate names, and the session's own expiry,
`min(sessionDeadlineMs, hostSessionKeyCertificate.validUntilMs)` (the
coordinator's deadline is session open + 10 minutes). The pinned helper
stores no deadline itself, so this record is the adapter's. A bind is
refused with `BIND_SESSION_NOT_VERIFIED` when the record is missing, names a
different session/role, or names a different address than the wallet, and
with `BIND_SESSION_EXPIRED` at or after the expiry. Agents must therefore
run the `verify-certificate` local action before binding, and bind within
the 10-minute session.

### Configuration: per-company key-id pins (required)

The tool is disabled until the adapter's environment pins which contract
token(s) and contract server(s) this company may bind:

```text
CLOCKCHAIN_LOCAL_ADAPTER_BIND_TOKEN_KEY_IDS=<keyId>[,<keyId>...]   # this company's CONTRACT_AUTH_TOKENS keyId(s)
CLOCKCHAIN_LOCAL_ADAPTER_BIND_SERVER_KEY_IDS=<keyId>[,<keyId>...]  # the contract server's CONTRACT_SERVER_KEY_ID
```

Each list holds 1–16 visible-ASCII key ids (≤ 64 chars), comma-separated,
surrounding spaces ignored. Unset, empty or malformed pins refuse every call
with `BIND_NOT_CONFIGURED`; a statement naming any other `tokenKeyId` or
`serverKeyId` is refused with `BIND_KEY_ID_NOT_ALLOWED`. Under launchd set
both in the root-owned plist's `EnvironmentVariables`, so the agent uid
cannot change them. List two server key ids only while rotating.

### Security: why this is not a signing oracle

- **No bytes in, one message shape out.** The tool takes no message, digest,
  bytes or path — only seven typed string fields, any extra/missing key
  refused, `domain` pinned to `agent-contract.bind/v1`, `runId` a UUID,
  `challenge` 64 lowercase hex, key ids visible ASCII ≤ 64. Every signature
  it can emit is over `sha256` of a JSON object of exactly that shape;
  making one verify for a different protocol message (a handshake proposal,
  acceptance, evidence, a transaction) would need a SHA-256 preimage.
- **Only held sessions, only the matching side.** The session directory and
  the role directory must already exist as private (0700, owned, non-symlink)
  directories with a `wallet.json`, and the helper's committed `policy.json`
  for that session must verify and name the same role. Nothing is created on
  refusal; a session the adapter does not hold, or the other side of one it
  does, is refused before any key is read.
- **Pinned to this company's token and server (L1).** Even the local agent
  cannot obtain a statement for a token or contract server outside the
  launchd-pinned lists, so a statement can never be handed to another
  principal's token.
- **Bound to one bind.** The contract server additionally requires
  `runId === certificate sessionId`, `tokenKeyId` = the calling token,
  `serverKeyId` = its own signer, a live single-use challenge issued to that
  token, and `issuedAt` inside the challenge window — so a statement cannot
  be replayed to another token, server, run or challenge.
- **Key never leaves.** The key is read inside `wallet-bridge`
  (`signExactBytes`, the same reader the helper uses) and only the signature
  and public address are returned.

Approval: like `authorize_local_action`, the tool is subject to the MCP
client's per-tool approval (`mcp__clockchain-local-adapter__sign_agent_contract_bind`);
the helper's local policy is the session gate above. A bind statement proves
key possession only — it authorizes no business action.

## Why not the shellCommand fallback

The `shellCommand` text remains in responses for compatibility clients, but
with the adapter installed the model should never transcribe it: the staged
step it executes is the same digest-bound command, validated locally, with the
payload bytes taken from the validated envelope — not from model output.
