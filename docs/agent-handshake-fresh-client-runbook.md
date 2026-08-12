# Fresh Codex + Claude Code Handshake Canary

This runbook proves the production stakeholder flow from two fresh clients in isolated empty workspaces. It does not clone a Clockchain repository into either client workspace, install a plugin, open a browser, share a role capability, or retain model credentials or private signing state.

## Public endpoint

Both clients connect to the same dedicated seven-tool endpoint:

`https://mcp.clockchain.network/handshake/mcp`

Equivalent one-time commands for manual clients are:

```text
codex mcp add clockchain-handshake --url https://mcp.clockchain.network/handshake/mcp
claude mcp add --transport http --scope user clockchain-handshake https://mcp.clockchain.network/handshake/mcp
```

The automated canary does not mutate the stakeholder's Claude configuration. It supplies that same endpoint inline with `--strict-mcp-config` for the one isolated process.

The endpoint instructions provide the pinned helper manifest URL, the SHA-256 of the exact manifest bytes, supported operations, and protocol loop. For today's Apple-device path, Node 24 is enforced and the harness preloads the single portable `clockchain-agent-handshake.cjs` bundle into each fresh workspace before either model starts. The adapter verifies the manifest digest and helper digest before writing those files. Every helper invocation is bound to the full MCP-returned command digest, but current production MCP still asks the agent to run only the short `approvalCommand` form: `clockchain-agent-authorize <64hex>`. That compact digest is a compatibility authorization token, not a transport payload. A private per-agent harness adapter verifies that digest against the signed immutable action record, validates the retained request length, operation, role, session, expiry, helper asset digests, and actual policy digest when the helper request carries one, then executes the retained structured argv directly. The model never supplies argv, and the model never transports the signing payload through shell text.

The adapter's action records are signed by an ephemeral parent key, live outside retained evidence, and disappear with the clean room. A retained action is one-use with a TTL. If helper assets are missing or fail pre-dispatch verification, the action is not consumed; under the normal preloaded path this should be impossible. Once dispatch begins, a helper process that exits nonzero is consumed fail-closed and requires a fresh MCP action rather than retrying the partially executed retained record. Claude receives no general `Write` permission, but Bash is still general within the configured sandbox; a local `node` shim refuses direct helper operations so the approval boundary cannot silently fall back. Authorization evidence is accepted only from the digest-bound adapter execution plus parent certificate verification. The local helper creates the role key, commits the exact local policy, registers a fresh ERC-8004 identity when the Initiator requires it, signs only policy-approved bytes, and verifies the final host certificate. The MCP server never receives a private key.

## Preflight

The canary remains disabled until all four values below agree with the independently published checksum-pinned helper release and the production host root:

- `CLOCKCHAIN_MCP_RELEASE_MANIFEST_DIGEST`
- `CLOCKCHAIN_RESEARCH_RELEASE_MANIFEST_DIGEST`
- `CLOCKCHAIN_MCP_HOST_ROOT_FINGERPRINTS`
- `CLOCKCHAIN_RESEARCH_HOST_ROOT_FINGERPRINTS`

Set `CLOCKCHAIN_RESEARCH_MONITOR_URL=https://clockchain-research.vercel.app/api/handshake/monitor`. Set `CLOCKCHAIN_FRESH_AGENT_RESULT_DIR` to an explicit private directory where the attempt artifact will be written. Codex may copy its private `~/.codex/auth.json` into its disposable home. Current Claude Code can use an existing interactive macOS Keychain login when the operator explicitly sets `CLOCKCHAIN_CLAUDE_EXISTING_LOGIN=1`; the Keychain credential is never extracted, printed, copied, or made available to the agent. The runner asks the authenticated Claude CLI to confirm its existing first-party login; it contains no OS credential-store reader. The Claude process retains the real macOS home only for first-party authentication. Its agent runs from an empty workspace with CLAUDE.md, auto-memory, bundled skills, workflows, plugins, hooks, slash commands, session persistence, and inherited MCP configuration disabled. The launch uses `--strict-mcp-config` with only Clockchain, and the tool sandbox denies reads and writes to the real home. Only a fixed allowlist of non-secret macOS session variables is inherited. Claude's Node helper execution sets `NODE_USE_ENV_PROXY=1` so Node 24 honors the sandbox's own network proxy; the allowed domains remain exactly the two Sepolia RPC endpoints. Claude's official inference-only `claude setup-token` via `CLAUDE_CODE_OAUTH_TOKEN` remains an alternative for fully disposable automation; it is not required for this approved Apple-device canary. API keys are optional alternatives: when `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` is present, the harness passes that key only to the matching disposable client process. Every supplied credential is also treated as a secret canary and must be absent from retained proof.

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
