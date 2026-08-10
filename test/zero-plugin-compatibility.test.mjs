import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { agentDescriptorDigest, verifyAgentDescriptorEnvelope } from "../src/agent-handshake/descriptor.mjs";
import { verifyAgentHandshakeEvidence } from "../src/agent-handshake/evidence.mjs";
import { agentTransitionDigest, validateAgentTransitionChain } from "../src/agent-handshake/protocol.mjs";
import { verifyAgentHandshakeResult } from "../src/agent-handshake/result.mjs";
import {
  agentHandshakeAcceptanceDigest,
  agentHandshakeProposalDigest,
  agentHandshakeStatementDigest,
  validateAgentHandshakeTerms,
  verifyAgentHandshakeAcceptance,
  verifyAgentHandshakeProposal,
} from "../src/agent-handshake/statement.mjs";
import { canonicalBytes, digestHex } from "../src/core/canonical.mjs";
import { transitionDigest } from "../src/core/messages.mjs";

async function fixture(name) {
  return JSON.parse(await readFile(new URL(`fixtures/${name}`, import.meta.url), "utf8"));
}

function decode(entry) {
  return JSON.parse(Buffer.from(entry.canonicalBase64url, "base64url").toString("utf8"));
}

function assertCanonical(entry, digest) {
  const value = decode(entry);
  assert.equal(canonicalBytes(value).toString("base64url"), entry.canonicalBase64url);
  assert.equal(digest(value), entry.protocolDigest);
  return value;
}

test("generic v1 canonical bytes, signatures, transitions, evidence, and certificate stay frozen", async () => {
  const captured = await fixture("agent-handshake-v1-wire.json");
  assert.equal(captured.schema, "clockchain.agent-handshake-v1-wire-fixture/v1");

  const terms = assertCanonical(captured.entries.terms, agentHandshakeStatementDigest);
  assert.deepEqual(validateAgentHandshakeTerms(terms), terms);
  const proposal = assertCanonical(captured.entries.proposal, agentHandshakeProposalDigest);
  const acceptance = assertCanonical(captured.entries.acceptance, agentHandshakeAcceptanceDigest);
  const descriptor = assertCanonical(captured.entries.descriptor, digestHex);
  const transitions = [
    assertCanonical(captured.entries.proposed, agentTransitionDigest),
    assertCanonical(captured.entries.accepted, agentTransitionDigest),
    assertCanonical(captured.entries.acknowledged, agentTransitionDigest),
  ];
  const initiatorEvidence = assertCanonical(captured.entries.initiatorEvidence, digestHex);
  const responderEvidence = assertCanonical(captured.entries.responderEvidence, digestHex);
  const result = assertCanonical(captured.entries.result, digestHex);

  await verifyAgentHandshakeProposal({
    envelope: proposal,
    expectedRepositorySha: captured.constants.repositorySha,
    expectedSessionId: captured.constants.sessionId,
    expectedTerms: terms,
    nowMs: Number(captured.constants.nowMs),
  });
  await verifyAgentHandshakeAcceptance({
    envelope: acceptance,
    proposalEnvelope: proposal,
    expectedRepositorySha: captured.constants.repositorySha,
    expectedSessionId: captured.constants.sessionId,
    expectedTerms: terms,
    nowMs: Number(captured.constants.nowMs),
  });
  const verifiedDescriptor = verifyAgentDescriptorEnvelope(descriptor, {
    expectedPublicKey: captured.constants.operatorPublicKey,
  });
  assert.equal(agentDescriptorDigest(verifiedDescriptor.descriptor), transitions[0].sessionDigest);
  validateAgentTransitionChain(transitions);

  const transitionDigests = transitions.map(agentTransitionDigest);
  for (const [role, envelope] of [["initiator", initiatorEvidence], ["responder", responderEvidence]]) {
    await verifyAgentHandshakeEvidence({
      envelope,
      expectedParty: transitions[0][role],
      expectedReference: terms.reference,
      expectedRepositorySha: captured.constants.repositorySha,
      expectedRole: role,
      expectedSessionDigest: transitions[0].sessionDigest,
      expectedStatementDigest: transitions[0].statementDigest,
      expectedTransitionDigests: transitionDigests,
    });
    const proof = verifyAgentHandshakeResult(result, {
      expectedParty: transitions[0][role],
      expectedPublicKey: captured.constants.operatorPublicKey,
      expectedRole: role,
      expectedSessionId: captured.constants.sessionId,
    });
    assert.equal(proof.certificateVerified, true);
  }
});

test("bilateral v1 transition bytes and digests stay frozen", async () => {
  const captured = await fixture("bilateral-wire-digests.json");
  assert.equal(captured.schema, "clockchain.bilateral-wire-digests/v1");
  for (const name of ["proposal", "acceptance", "acknowledgment"]) {
    assertCanonical(captured.transitions[name], transitionDigest);
  }
});
