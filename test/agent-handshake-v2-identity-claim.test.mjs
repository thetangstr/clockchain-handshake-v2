import assert from "node:assert/strict";
import test from "node:test";

import { canonicalBytes } from "../src/core/canonical.mjs";
import {
  verifyAgentHandshakeV2IdentityClaimEnvelope,
} from "../src/agent-handshake/v2/identity-claim.mjs";
import {
  INITIATOR,
  REPOSITORY_SHA,
  SESSION_ID,
  TERMS,
} from "./support/agent-handshake-v2-fixture.mjs";
import { agentHandshakeV2StatementDigest } from "../src/agent-handshake/v2/terms.mjs";

const claim = {
  schema: "clockchain.agent-handshake-identity-claim/v2",
  protocol: "clockchain.agent-handshake/v2",
  sessionId: SESSION_ID,
  repositorySha: REPOSITORY_SHA,
  role: "initiator",
  sessionKeyAddress: INITIATOR.address.toLowerCase(),
  policyDigest: "a".repeat(64),
  statementDigest: agentHandshakeV2StatementDigest(TERMS),
  externalBusinessActionPerformed: false,
};

async function envelope(overrides = {}) {
  const value = { ...claim, ...overrides };
  return {
    claim: value,
    signature: {
      address: INITIATOR.address.toLowerCase(),
      algorithm: "eip191",
      value: await INITIATOR.signMessage({ message: { raw: canonicalBytes(value) } }),
    },
  };
}

test("the host verifies the exact local identity claim before accepting its address", async () => {
  const verified = await verifyAgentHandshakeV2IdentityClaimEnvelope(
    await envelope(),
    {
      expectedRepositorySha: REPOSITORY_SHA,
      expectedRole: "initiator",
      expectedSessionId: SESSION_ID,
      expectedStatementDigest: agentHandshakeV2StatementDigest(TERMS),
    },
  );
  assert.deepEqual(verified.claim, claim);
});

test("foreign signatures, changed bindings, and unknown fields fail closed", async () => {
  const good = await envelope();
  for (const candidate of [
    { ...good, extra: true },
    { ...good, claim: { ...good.claim, policyDigest: "b".repeat(64) } },
    await envelope({ role: "responder" }),
    { ...good, signature: { ...good.signature, address: "0x" + "f".repeat(40) } },
  ]) {
    await assert.rejects(() => verifyAgentHandshakeV2IdentityClaimEnvelope(candidate, {
      expectedRepositorySha: REPOSITORY_SHA,
      expectedRole: "initiator",
      expectedSessionId: SESSION_ID,
      expectedStatementDigest: agentHandshakeV2StatementDigest(TERMS),
    }));
  }
});
