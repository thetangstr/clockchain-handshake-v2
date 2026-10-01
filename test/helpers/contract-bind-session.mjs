// Lays down a handshake session exactly as the pinned helper's init + policy
// steps leave it: <tmpRoot>/.clockchain/handshakes/<sessionId>/<role> at
// 0700, wallet.json (0600) via wallet-bridge, and the committed policy.json.
// Keys are PUBLIC test keys derived from a label — never real wallets, and
// derived rather than written out so no key-shaped literal is committed.

import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";

import { privateKeyToAccount } from "viem/accounts";

import { commitAgentPolicy } from "../../src/agent-cli/policy.mjs";
import { initializeWallet } from "../../src/core/wallet-bridge.mjs";
import { recordVerifiedSession } from "../../src/local-adapter/contract-bind.mjs";

// Far-future default so fixed-clock vectors stay valid; L3 tests pass their own.
export const FAR_FUTURE_MS = Date.parse("2100-01-01T00:00:00.000Z");

export function testSessionKey(label) {
  const privateKey = `0x${createHash("sha256").update(`clockchain-local-adapter/contract-bind-test-key/${label}`).digest("hex")}`;
  return Object.freeze({
    privateKey,
    address: privateKeyToAccount(privateKey).address.toLowerCase(),
  });
}

export const TEST_POLICY = Object.freeze({
  schema: "clockchain.agent-handshake-policy/v1",
  protocol: "clockchain.agent-handshake/v2",
  role: "initiator",
  mcpOrigin: "https://mcp.clockchain.network",
  reference: "NS-1847",
  statementDigest: "e".repeat(64),
  maxValidForSeconds: "90",
  identityPolicy: Object.freeze({ erc8004: "not_required", chainId: null, registryAddress: null }),
  externalBusinessActionsAllowed: false,
});

// verified: also leave the record the adapter writes after this role's
// verify-certificate step succeeded (sessionKeyAddress + expiry).
export async function layDownSession(tmpRoot, {
  sessionId, role, privateKey, verified = true, expiresAtMs = FAR_FUTURE_MS,
}) {
  const stateDir = join(tmpRoot, ".clockchain", "handshakes", sessionId, role);
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  await initializeWallet({ statePath: join(stateDir, "wallet.json"), generatePrivateKey: () => privateKey });
  await commitAgentPolicy({ stateDir, policy: { ...TEST_POLICY, role } });
  if (verified) {
    const recorded = await recordVerifiedSession({
      stateDir, sessionId, role,
      sessionKeyAddress: privateKeyToAccount(privateKey).address.toLowerCase(),
      expiresAtMs,
    });
    if (!recorded) throw new Error("test fixture could not record the verified session");
  }
  return stateDir;
}
