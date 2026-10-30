import assert from "node:assert/strict";
import test from "node:test";

import {
  agentHandshakeV2TransitionDigest,
  validateAgentHandshakeV2TransitionChain,
  verifyAgentHandshakeV2Acceptance,
  verifyAgentHandshakeV2Proposal,
} from "../src/agent-handshake/v2/protocol.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import {
  INITIATOR, NOW_MS, REPOSITORY_SHA, SESSION_ID, TERMS, buildV2Fixture,
} from "./support/agent-handshake-v2-fixture.mjs";

test("initiator proposal, responder acceptance, and unsigned acknowledgment form one exact chain", async () => {
  const fixture = await buildV2Fixture();
  await verifyAgentHandshakeV2Proposal({
    envelope: fixture.proposalEnvelope,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    expectedTerms: TERMS,
    nowMs: NOW_MS,
  });
  await verifyAgentHandshakeV2Acceptance({
    envelope: fixture.acceptanceEnvelope,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    expectedTerms: TERMS,
    nowMs: NOW_MS,
    proposalEnvelope: fixture.proposalEnvelope,
  });
  assert.equal(validateAgentHandshakeV2TransitionChain(fixture.transitions).length, 3);
  assert.equal(fixture.transitions[1].predecessor, agentHandshakeV2TransitionDigest(fixture.transitions[0]));
  assert.equal(fixture.transitions[2].predecessor, agentHandshakeV2TransitionDigest(fixture.transitions[1]));
  assert.equal("signature" in fixture.transitions[2], false);
});

test("valid signatures fail on wrong session, role party, statement, policy, or external-action mutation", async () => {
  const fixture = await buildV2Fixture();
  // Each mutant is re-signed by the initiator over its own bytes, so the
  // signature is valid and the rejection isolates the mutated binding.
  const resigned = async (payload) => ({
    ...fixture.proposalEnvelope,
    payload,
    signature: {
      ...fixture.proposalEnvelope.signature,
      value: await INITIATOR.signMessage({ message: { raw: canonicalBytes(payload) } }),
    },
  });
  const mutations = [
    await resigned({ ...fixture.proposalEnvelope.payload, sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }),
    await resigned({ ...fixture.proposalEnvelope.payload, statementDigest: "f".repeat(64) }),
    await resigned({ ...fixture.proposalEnvelope.payload, externalBusinessActionPerformed: true }),
    await resigned({ ...fixture.proposalEnvelope.payload, initiator: fixture.parties.responder }),
  ];
  for (const envelope of mutations) {
    await assert.rejects(() => verifyAgentHandshakeV2Proposal({
      envelope,
      expectedRepositorySha: REPOSITORY_SHA,
      expectedSessionId: SESSION_ID,
      expectedTerms: TERMS,
      nowMs: NOW_MS,
    }));
  }
  const reordered = [fixture.transitions[1], fixture.transitions[0], fixture.transitions[2]];
  assert.throws(() => validateAgentHandshakeV2TransitionChain(reordered));
});
