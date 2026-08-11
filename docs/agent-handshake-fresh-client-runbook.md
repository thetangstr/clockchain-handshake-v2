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

The endpoint instructions provide the pinned helper manifest URL, the SHA-256 of the exact manifest bytes, supported operations, and protocol loop. For today's Apple-device path, Node 24 is enforced and the fresh client downloads the single portable `clockchain-agent-handshake.cjs` bundle. Every helper invocation runs through one fixed bootstrap command that hashes the exact manifest bytes against the independently agreed pin, requires the manifest `nodeRuntime` and executing process to be Node 24.x, reads the helper SHA-256 from that verified manifest, hashes the helper, and executes only those already-verified helper bytes from memory. Claude receives no general `Write` permission, but Bash is still general within the configured sandbox. Authorization evidence is accepted only from the exact pinned helper command plus parent verification. The local helper creates the role key, commits the exact local policy, registers a fresh ERC-8004 identity when the Initiator requires it, signs only policy-approved bytes, and verifies the final host certificate. The MCP server never receives a private key.

## Preflight

The canary remains disabled until all four values below agree with the independently published checksum-pinned helper release and the production host root:

- `CLOCKCHAIN_MCP_RELEASE_MANIFEST_DIGEST`
- `CLOCKCHAIN_RESEARCH_RELEASE_MANIFEST_DIGEST`
- `CLOCKCHAIN_MCP_HOST_ROOT_FINGERPRINTS`
- `CLOCKCHAIN_RESEARCH_HOST_ROOT_FINGERPRINTS`

Set `CLOCKCHAIN_RESEARCH_MONITOR_URL=https://clockchain-research.vercel.app/api/handshake/monitor`. Set `CLOCKCHAIN_FRESH_AGENT_RESULT_DIR` to an explicit private directory where the attempt artifact will be written. Codex may copy its private `~/.codex/auth.json` into its disposable home. Current Claude Code stores an interactive macOS login in the encrypted macOS Keychain; that Keychain entry is deliberately not extracted or made visible to a disposable client. For the automated empty-home canary, generate Claude's official inference-only automation credential with `claude setup-token` and supply it as `CLAUDE_CODE_OAUTH_TOKEN`. API keys are optional alternatives: when `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` is present, the harness passes that key only to the matching disposable client process. Every supplied credential is also treated as a secret canary and must be absent from retained proof.

Node 24 is enforced before starting either fresh client. On this demo Mac, the isolated runtime is `/opt/homebrew/opt/node@24/bin/node`; launch the canary with `/opt/homebrew/opt/node@24/bin` first in `PATH`. The same validated runtime directory is prepended to child process `PATH` so helper `node` execution resolves to the checked runtime. No Apple Developer account, notarization credential, npm login, plugin, or repository checkout is required for this Apple-device demo path.

## Run

```bash
node scripts/run-fresh-agent-handshake.mjs
```

By default Codex is the Initiator and Claude Code is the Responder. Reverse them with:

```bash
CLOCKCHAIN_INITIATOR_CLIENT=claude CLOCKCHAIN_RESPONDER_CLIENT=codex node scripts/run-fresh-agent-handshake.mjs
```

The automated canary starts the Initiator first, reads the actual single-use Responder invitation from the structured MCP tool event in memory, and only then starts the Responder. The invitation is sent to the Responder over stdin, never a process argument, and is included in the retained-evidence secret scan. In the two-person stakeholder demonstration, the Initiator shows that same invitation and the first person copies only it into the second person's fresh client. The Initiator role capability is never copied.

## Required terminal proof

Success requires both clients to report the same session and certificate digest, distinct addresses, policies, and ERC-8004 agent ids, three receipt ids, `certificateVerified: true`, and `externalBusinessActionPerformed: false`. The Research monitor must independently report checker `VERIFIED` and a closing certificate for that session.

The retained JSON contains only public evidence. Disposable homes, workspaces, caches, client configuration, helper state, local keys, role capabilities, invitations, transcripts, and raw stdout/stderr are removed on success and failure.

## Known Codex boundary

Codex `workspace-write` isolates the fresh workspace but does not promise literal per-command pattern enforcement. The helper itself therefore accepts only six fixed operations, exact base64url payloads, a descendant state directory, an immutable release URL, and digest verification. This limitation is recorded; it is not represented as a stronger sandbox guarantee.
