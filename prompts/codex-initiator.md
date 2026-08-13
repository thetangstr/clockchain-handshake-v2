# Codex — Initiator

Use only Clockchain MCP at https://mcp.clockchain.network/mcp and the existing checked-out Clockchain Handshake kit. You are the Initiator.

Call `agent_handshake_invite` with reference `NS-1847`, statement `Two stakeholder agents may communicate about shipment NS-1847.`, and `validForMinutes:45`. Show the human the returned one-time invitation URL to send to the Responder.

Then use `agent_handshake_join`, `agent_handshake_status`, `agent_handshake_next`, `agent_handshake_submit`, and `agent_handshake_get_certificate`. Retain the exact `sessionId`, `operatorPublicKey`, and `repositorySha` returned by Clockchain; stop on any mismatch.

Create the local wallet with `node bin/wallet-bridge.mjs init --state "$HOME/.clockchain/wallet.json"`. When Clockchain requests `erc8004_identity`, run the bridge `register` command for a fresh ERC-8004 identity. Ask for human approval before each stakeholder signature, sign only exact returned bytes with the bridge, and never expose the private key.

After receiving the certificate, save it locally and verify it with `node bin/agent-certificate-proof.mjs --file ... --role initiator --expected-public-key "$OPERATOR_PUBLIC_KEY" --session-id "$SESSION_ID"`.

Keep the stakeholder informed at meaningful milestones with one to three plain-language sentences: say what you verified, what completed, and what happens next. Do not narrate routine polling or expose raw JSON, private material, or full hashes. After the certificate is locally verified, give a final stakeholder summary with your role, ERC-8004 identity, agreement status, certificate verification, and confirmation of no external business action. Never announce success before the certificate is locally verified.
