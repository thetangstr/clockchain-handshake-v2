# Hosted stranger dry run

This runbook is for the P4 pre-dry-run path: the already-running AWS host,
public relay, and one discovery URL for both outside agents.

Discovery URL:

```text
http://44.249.47.220:8080/v1/discovery/current
```

Monitor URL:

```text
http://44.249.47.220:8080/monitor/current
```

## Before Inviting People

Check the hosted relay:

```bash
curl -s http://44.249.47.220:8080/healthz
```

Expect JSON with `"ok":true` and `"paymentMoved":false`.

Check the Clockchain MCP endpoint the kits write through:

```bash
curl -s https://mcp.clockchain.network/health
```

Expect a healthy JSON response before inviting either side.

Fetch the current discovery JSON:

```bash
curl -s http://44.249.47.220:8080/v1/discovery/current
```

Expect JSON with `sessionId`, `relayUrl`, and `operatorPublicKey`. The field is
still named `operatorPublicKey` on the wire; public instructions call it the
session host key.

Open the monitor URL above. It should either show the current session or keep
retrying until the AWS host publishes the next one.

This is a single-validator testnet, not mainnet or court-grade evidence. The
only funds involved are Sepolia test-network gas for identity registration. No
payment, bank, card, customer account, or mainnet wallet moves.

## Send These Instructions

Send the requestor `prompts/requestor.md` and replace `<DISCOVERY_URL>` with:

```text
http://44.249.47.220:8080/v1/discovery/current
```

Send the payer `prompts/payer.md` and replace `<DISCOVERY_URL>` with the same
URL.

There is no relay URL, session id, key, token, password, or repository SHA for
either person to assemble. The invitation document supplies and validates the
session, relay, and host key.

## Clean-Clone Commands

Requestor:

```bash
git clone -b codex/handshake-build https://github.com/thetangstr/clockchain-handshake-v2.git
cd clockchain-handshake-v2
npm ci
node bin/requestor.mjs --discovery-url <DISCOVERY_URL>
```

Payer:

```bash
git clone -b codex/handshake-build https://github.com/thetangstr/clockchain-handshake-v2.git
cd clockchain-handshake-v2
npm ci
node bin/payer.mjs --discovery-url <DISCOVERY_URL>
```

Both sides should run `node --version` first and require Node 22 or higher.

## What To Watch

The board's middle lane is:

```text
Clockchain — session host & independent checker.
```

That is display copy only. Internally the snapshot role remains `verifier`.

The board should show no verdict until the signed closing certificate exists.
Each side should print that its own completion is not approval. If a certificate
arrives, each side verifies it against the host key from the discovery
invitation before reporting what the certificate says.

## Failure Handling

A stopped run is not a broken demo. It is the system refusing to claim something
it cannot prove.

Common public reasons:

| Reason | Meaning |
|---|---|
| `EXPIRED` | A participant or ledger step took too long. Start a fresh session. |
| `MISSING` | Evidence from one side did not arrive. Check that side's terminal. |
| `RENDEZVOUS_UNAVAILABLE` | The relay or ledger could not be reached. Pause the run. |
| `MALFORMED` | A message or artifact did not match the expected shape. Rerun once; if repeated, investigate. |
| `ROLE_ALREADY_BOUND` | A second agent tried to take a role already claimed in this session. Start fresh. |

Do not explain a failure as success. Read the printed sentence and reason code.

## Proof Moment

When the run completes, use the block heights printed by the certificate to read
the public ledger:

```bash
node -e '
const { createMcpClient, mintDemoToken } = await import("./src/core/clockchain.mjs");
const c = createMcpClient({ token: await mintDemoToken({}) });
for (const h of [/* paste block heights here */]) {
  const b = await c.getBlock({ height: h });
  console.log("block", b.blockHeight, "recorded at", b.blockTime);
}'
```

The claim is ordering and matching evidence: terms, acceptance, acknowledgment,
then a hosted independent check. It does not prove production readiness,
consensus security, legal sufficiency, or adversarial robustness.
