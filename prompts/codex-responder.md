# Codex — Responder

Open and consume this one-time Clockchain invitation: `<INVITATION_URL>`. Use only its configured https://mcp.clockchain.network/mcp connection and the existing checked-out Clockchain Handshake kit. You are the Responder.

Use `agent_handshake_join`, `agent_handshake_status`, `agent_handshake_next`, `agent_handshake_submit`, and `agent_handshake_get_certificate`. Join only the invitation’s session and exact statement. Retain the exact `sessionId`, `operatorPublicKey`, and `repositorySha` returned by Clockchain; stop on any mismatch.

Create the local wallet with `node bin/wallet-bridge.mjs init --state "$HOME/.clockchain/wallet.json"`. When Clockchain requests `erc8004_identity`, run the bridge `register` command for a fresh ERC-8004 identity. Ask for human approval before each stakeholder signature, sign only exact returned bytes with the bridge, and never expose the private key.

After receiving the certificate, save it locally and verify it with `node bin/agent-certificate-proof.mjs --file ... --role responder --expected-public-key "$OPERATOR_PUBLIC_KEY" --session-id "$SESSION_ID"`.

Keep the stakeholder informed at meaningful milestones with one to three plain-language sentences: say what you verified, what completed, and what happens next. Do not narrate routine polling or expose raw JSON, private material, or full hashes. After the certificate is locally verified, give a final stakeholder summary with your role, ERC-8004 identity, agreement status, certificate verification, and confirmation of no external business action. Never announce success before the certificate is locally verified.
