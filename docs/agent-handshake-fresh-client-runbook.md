# Fresh Codex + Claude Code Handshake Canary

This runbook proves the production stakeholder flow from two empty client homes. It does not clone a Clockchain repository into either client workspace, install a plugin, open a browser, share a role capability, or retain model credentials or private signing state.

## Public endpoint

Both clients connect to the same dedicated seven-tool endpoint:

`https://mcp.clockchain.network/handshake/mcp`

One-time commands inside the disposable homes are:

```text
codex mcp add clockchain-handshake --url https://mcp.clockchain.network/handshake/mcp
claude mcp add --transport http --scope user clockchain-handshake https://mcp.clockchain.network/handshake/mcp
```

The endpoint instructions provide the verified helper release URL, digest, supported operations, and protocol loop. The local helper creates the role key, commits the exact local policy, registers a fresh ERC-8004 identity when the Initiator requires it, signs only policy-approved bytes, and verifies the final host certificate. The MCP server never receives a private key.

## Preflight

The canary remains disabled until all four values below agree with the independently published signed helper release and the production host root:

- `CLOCKCHAIN_MCP_RELEASE_MANIFEST_DIGEST`
- `CLOCKCHAIN_RESEARCH_RELEASE_MANIFEST_DIGEST`
- `CLOCKCHAIN_MCP_HOST_ROOT_FINGERPRINTS`
- `CLOCKCHAIN_RESEARCH_HOST_ROOT_FINGERPRINTS`

Set `CLOCKCHAIN_RESEARCH_MONITOR_URL=https://clockchain-research.vercel.app/api/handshake/monitor`. Supply model authentication through `OPENAI_API_KEY` and/or `ANTHROPIC_API_KEY`; the harness passes it only to the disposable client processes and scans retained proof for the exact canary values.

## Run

```bash
node scripts/run-fresh-agent-handshake.mjs
```

By default Codex is the Initiator and Claude Code is the Responder. Reverse them with:

```bash
CLOCKCHAIN_INITIATOR_CLIENT=claude CLOCKCHAIN_RESPONDER_CLIENT=codex node scripts/run-fresh-agent-handshake.mjs
```

For a staged copy/paste demonstration, run the Initiator until it returns the single-use Responder invitation, then pass that exact value as `CLOCKCHAIN_RESPONDER_INVITATION` to the canary. Do not put the Initiator role capability in that variable.

## Required terminal proof

Success requires both clients to report the same session and certificate digest, distinct addresses, policies, and ERC-8004 agent ids, three receipt ids, `certificateVerified: true`, and `externalBusinessActionPerformed: false`. The Research monitor must independently reach `CERTIFIED` for that session.

The retained JSON contains only public evidence. Disposable homes, workspaces, caches, client configuration, helper state, local keys, role capabilities, invitations, transcripts, and raw stdout/stderr are removed on success and failure.

## Known Codex boundary

Codex `workspace-write` isolates the fresh workspace but does not promise literal per-command pattern enforcement. The helper itself therefore accepts only six fixed operations, exact base64url payloads, a descendant state directory, an immutable release URL, and digest verification. This limitation is recorded; it is not represented as a stronger sandbox guarantee.
