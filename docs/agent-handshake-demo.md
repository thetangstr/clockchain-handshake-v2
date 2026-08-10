# Two-stakeholder Clockchain Handshake demo

This run uses two separate computers and two fresh local agent sessions. One
person is the Initiator; the other is the Responder. Each agent creates its own
wallet and fresh ERC-8004 identity, reviews and signs its own stakeholder
artifacts, and independently verifies the same closing certificate.

## What each person needs

- Codex or Claude Code, authenticated to that product.
- Node.js 22 or newer, Git, and an empty working directory.
- Internet access to `https://mcp.clockchain.network/mcp` and Sepolia.
- The Initiator starts with a normal Clockchain MCP token. The Responder starts
  only with the one-time invitation URL sent by the Initiator.

Do not share MCP tokens, wallet files, private keys, workspaces, or agent state.
The invitation URL is a capability: send it directly to the intended Responder,
do not place it in chat logs, tickets, or screenshots, and use it once.

## Configure Codex

The current Codex CLI supports Streamable HTTP servers and bearer tokens held in
an environment variable:

```bash
export CLOCKCHAIN_MCP_TOKEN='the token issued to this stakeholder'
codex mcp add clockchain --url https://mcp.clockchain.network/mcp --bearer-token-env-var CLOCKCHAIN_MCP_TOKEN
codex mcp list
```

The equivalent `~/.codex/config.toml` entry is:

```toml
[mcp_servers.clockchain]
url = "https://mcp.clockchain.network/mcp"
bearer_token_env_var = "CLOCKCHAIN_MCP_TOKEN"
enabled_tools = [
  "agent_handshake_invite",
  "agent_handshake_status",
  "agent_handshake_join",
  "agent_handshake_next",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]
```

For a Responder-scoped credential, omit `agent_handshake_invite`; the server
also enforces that restriction. Official reference:
https://developers.openai.com/codex/mcp

## Configure Claude Code

Claude Code expands environment variables in HTTP headers stored in its MCP
configuration. Keep the token in the shell environment and preserve the literal
`${CLOCKCHAIN_MCP_TOKEN}` in the JSON:

```bash
export CLOCKCHAIN_MCP_TOKEN='the token issued to this stakeholder'
claude mcp add-json clockchain \
  '{"type":"http","url":"https://mcp.clockchain.network/mcp","headers":{"Authorization":"Bearer ${CLOCKCHAIN_MCP_TOKEN}"}}' \
  --scope local
claude mcp get clockchain
```

Official reference: https://code.claude.com/docs/en/mcp

## Initiator

1. Start a fresh Codex or Claude Code session with Clockchain MCP configured.
2. Paste `prompts/codex-initiator.md` or `prompts/claude-initiator.md`.
3. Review the exact reference, statement, and 45-minute window.
4. The agent calls `agent_handshake_invite`. Send the returned one-time URL
   directly to the Responder.
5. Continue in the same fresh session. Do not take actions for the Responder.

## Responder

1. Open the invitation URL. Its fragment is exchanged once for a Responder-only,
   session-bound Clockchain credential; the fragment is not sent in the page
   request or retained by the server.
2. Configure the returned credential in a fresh Codex or Claude Code session.
3. Replace `<INVITATION_URL>` in the matching Responder prompt and paste it.
4. Independently review the exact statement before approving a signature.

## Existing local wallet and live ERC-8004 registration

After `agent_handshake_join` returns `repositorySha`, each stakeholder obtains
the public kit and checks out that exact commit:

```bash
git clone https://github.com/thetangstr/clockchain-handshake-v2.git
cd clockchain-handshake-v2
git checkout "$REPOSITORY_SHA"
npm ci
node bin/wallet-bridge.mjs init --state "$HOME/.clockchain/wallet.json"
node bin/wallet-bridge.mjs inspect --state "$HOME/.clockchain/wallet.json"
```

The wallet stays local. Clockchain observes the public address, the host supplies
Sepolia registration gas to that exact seat, and `agent_handshake_next` returns
`needed:"erc8004_identity"`. Then the stakeholder approves one registration
transaction:

```bash
node bin/wallet-bridge.mjs register \
  --state "$HOME/.clockchain/wallet.json" \
  --displayName "Fresh stakeholder demo agent"
```

The resulting identity number, owner address, registry address, chain, and
registration transaction are public proof. Never print or transmit the private
key.

For every later signing request, pass the exact MCP-returned bytes directly to
the bridge and compare `bytesSha256` before submitting only `signatureHex`.
Human approval is required before each stakeholder signature.

## Completion proof

Both agents continue the five generic tools until
`agent_handshake_get_certificate` returns one nonempty certificate. Each saves
only that public envelope and verifies it against the discovery key and session:

```bash
node bin/agent-certificate-proof.mjs \
  --file "$HOME/clockchain-agent-handshake-certificate.json" \
  --role initiator \
  --expected-public-key "$OPERATOR_PUBLIC_KEY" \
  --session-id "$SESSION_ID"
```

The Responder uses `--role responder`. The demo is complete only when both local
proof commands succeed and the stakeholder page shows two distinct identities,
three ordered receipts, the independent checker result, and the signed
certificate.
