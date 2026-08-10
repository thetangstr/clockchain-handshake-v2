import assert from "node:assert/strict";
import test from "node:test";

import {
  verifyAgentHandshakeV2Evidence,
} from "../src/agent-handshake/v2/evidence.mjs";
import { agentHandshakeV2TransitionDigest } from "../src/agent-handshake/v2/protocol.mjs";
import { REPOSITORY_SHA, buildV2Fixture } from "./support/agent-handshake-v2-fixture.mjs";

test("each role independently signs evidence bound to its party, policy, and transition chain", async () => {
  const fixture = await buildV2Fixture();
  for (const role of ["initiator", "responder"]) {
    await verifyAgentHandshakeV2Evidence({
      envelope: fixture.evidence[role],
      expectedParty: fixture.parties[role],
      expectedPolicyDigest: fixture.parties[role].policyDigest,
      expectedReference: "NS-1847",
      expectedRepositorySha: REPOSITORY_SHA,
      expectedRole: role,
      expectedSessionDigest: fixture.transitions[0].sessionDigest,
      expectedStatementDigest: fixture.transitions[0].statementDigest,
      expectedTransitionDigests: fixture.transitions.map(agentHandshakeV2TransitionDigest),
      identityPolicy: fixture.descriptorEnvelope.descriptor.identityPolicy,
    });
  }
});

test("role, party, policy, statement, receipt digest, and external-action mutations fail", async () => {
  const fixture = await buildV2Fixture();
  const base = fixture.evidence.initiator;
  for (const result of [
    { ...base.result, role: "responder" },
    { ...base.result, party: fixture.parties.responder },
    { ...base.result, policyDigest: "f".repeat(64) },
    { ...base.result, statementDigest: "f".repeat(64) },
    { ...base.result, transitionDigests: ["f".repeat(64), ...base.result.transitionDigests.slice(1)] },
    { ...base.result, externalBusinessActionPerformed: true },
  ]) {
    await assert.rejects(() => verifyAgentHandshakeV2Evidence({
      envelope: { ...base, result },
      expectedParty: fixture.parties.initiator,
      expectedPolicyDigest: fixture.parties.initiator.policyDigest,
      expectedReference: "NS-1847",
      expectedRepositorySha: REPOSITORY_SHA,
      expectedRole: "initiator",
      expectedSessionDigest: fixture.transitions[0].sessionDigest,
      expectedStatementDigest: fixture.transitions[0].statementDigest,
      expectedTransitionDigests: fixture.transitions.map(agentHandshakeV2TransitionDigest),
      identityPolicy: fixture.descriptorEnvelope.descriptor.identityPolicy,
    }));
  }
});
