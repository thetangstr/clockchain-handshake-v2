#!/usr/bin/env node
// Regenerates test/fixtures/agent-contract-bind-vectors.json: bind statements
// signed by the adapter's sign_agent_contract_bind path, with the canonical
// JSON, digest and recovered address computed by the REAL agent-contract
// server code (clockchain-developer-tools mcp-server src/agent-contract,
// bundled locally — see test/helpers/agent-contract-server.mjs). The fixture
// lets the hermetic suite prove server parity without that repository.
// Local only: no network, no real keys (public label-derived test keys).
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { signContractBindStatement } from "../src/local-adapter/contract-bind.mjs";
import { loadAgentContractServer } from "../test/helpers/agent-contract-server.mjs";
import { layDownSession, testSessionKey } from "../test/helpers/contract-bind-session.mjs";

export const BIND_VECTOR_CASES = Object.freeze([
  {
    keyLabel: "vector-0",
    statement: {
      domain: "agent-contract.bind/v1",
      runId: "11111111-2222-4333-8444-555555555555",
      side: "initiator",
      tokenKeyId: "klb1",
      serverKeyId: "contract-server",
      challenge: "c0ffee".padEnd(64, "0"),
      issuedAt: "2026-10-01T17:00:00.000Z",
    },
  },
  {
    keyLabel: "vector-1",
    statement: {
      domain: "agent-contract.bind/v1",
      runId: "deadbeef-0010-4444-8888-000000000010",
      side: "responder",
      tokenKeyId: "travel-provider.late_2",
      serverKeyId: "ephemeral-dev-0123456789abcdef",
      challenge: "0123456789abcdef".repeat(4),
      issuedAt: "2026-10-01T17:00:59Z",
    },
  },
]);

async function main() {
  const server = await loadAgentContractServer();
  if (server === null) throw new Error("agent-contract server source not found (set CLOCKCHAIN_AGENT_CONTRACT_SRC)");
  const vectors = [];
  for (const { keyLabel, statement } of BIND_VECTOR_CASES) {
    const tmpRoot = await mkdtemp(join(tmpdir(), "bind-vectors-"));
    try {
      const key = testSessionKey(keyLabel);
      await layDownSession(tmpRoot, { sessionId: statement.runId, role: statement.side, privateKey: key.privateKey });
      const signed = await signContractBindStatement(statement, {
        nowMs: Date.parse(statement.issuedAt), tmpRoot,
        tokenKeyIds: [statement.tokenKeyId], serverKeyIds: [statement.serverKeyId],
      });
      const digest = server.canonicalDigest(statement);
      const digestBytes = Buffer.from(digest.slice(2), "hex");
      const recovered = server.eip191RecoverPublicKey(digestBytes, signed.signature);
      vectors.push({
        keyLabel,
        statement,
        canonicalJson: server.canonicalJson(statement),
        digest,
        signature: signed.signature,
        serverCanonicalSignature: server.isCanonicalEip191Signature(signed.signature),
        serverRecoveredAddress: recovered === null ? null : server.publicKeyToAddress(recovered).toLowerCase(),
      });
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  }
  const fixture = {
    schema: "clockchain.local-adapter.agent-contract-bind-vectors/v1",
    source: `clockchain-developer-tools packages/mcp-server src/agent-contract @ ${server.sourceCommit} (canonical.ts canonicalJson/canonicalDigest, eip191.ts eip191RecoverPublicKey/isCanonicalEip191Signature/publicKeyToAddress)`,
    keyDerivation: "privateKey = 0x || sha256(\"clockchain-local-adapter/contract-bind-test-key/\" || keyLabel) — public test keys",
    vectors,
  };
  const target = new URL("../test/fixtures/agent-contract-bind-vectors.json", import.meta.url);
  await writeFile(target, `${JSON.stringify(fixture, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({ ok: true, vectors: vectors.length, source: server.sourceCommit })}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    process.stderr.write(`${error?.message ?? error}\n`);
    process.exitCode = 1;
  });
}
