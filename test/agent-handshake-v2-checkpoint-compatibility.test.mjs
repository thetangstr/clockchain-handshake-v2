import assert from "node:assert/strict";
import test from "node:test";

import { digestHex } from "../src/core/canonical.mjs";
import {
  commitmentCheckpointDigest,
  signAgentHandshakeV2CommitmentCheckpoint,
  verifyAgentHandshakeV2CommitmentCheckpointChain,
} from "../src/agent-handshake/v2/commitment-checkpoint.mjs";
import {
  agentHandshakeV2TransitionDigest,
  validateAgentHandshakeV2TransitionChain,
  verifyAgentHandshakeV2Acceptance,
  verifyAgentHandshakeV2Proposal,
} from "../src/agent-handshake/v2/protocol.mjs";
import { verifyAgentHandshakeV2Evidence } from "../src/agent-handshake/v2/evidence.mjs";
import { verifyAgentHandshakeV2Authorization } from "../src/agent-handshake/v2/verdict.mjs";
import {
  INITIATOR,
  NOW_MS,
  REPOSITORY_SHA,
  RESPONDER,
  SESSION_ID,
  TERMS,
  buildV2Fixture,
} from "./support/agent-handshake-v2-fixture.mjs";

async function signedCheckpoint({ account, role, artifactType, artifactDigest, sequence, previousCheckpointDigest = null }) {
  return signAgentHandshakeV2CommitmentCheckpoint({
    checkpoint: {
      schema: "clockchain.agent-handshake-commitment-checkpoint/v1",
      version: "1",
      protocol: "clockchain.agent-handshake/v2",
      sessionId: SESSION_ID,
      role,
      artifactType,
      artifactDigest,
      sequence,
      previousCheckpointDigest,
      issuedAtMs: "1786337160000",
      expiresAtMs: "1786337190000",
      signerAddress: account.address.toLowerCase(),
    },
    signMessage: (raw) => account.signMessage({ message: { raw } }),
  });
}

async function checkpointPair(fixture, overrides = {}) {
  const proposed = await signedCheckpoint({
    account: INITIATOR,
    role: "initiator",
    artifactType: "proposal",
    artifactDigest: overrides.proposalDigest ?? digestHex(fixture.proposalEnvelope),
    sequence: "1",
  });
  const accepted = await signedCheckpoint({
    account: RESPONDER,
    role: "responder",
    artifactType: "acceptance",
    artifactDigest: overrides.acceptanceDigest ?? digestHex(fixture.acceptanceEnvelope),
    sequence: "2",
    previousCheckpointDigest: commitmentCheckpointDigest(proposed),
  });
  return [proposed, accepted];
}

async function checkpointPathWithCounterproposal(fixture) {
  const counterproposed = await signedCheckpoint({
    account: RESPONDER,
    role: "responder",
    artifactType: "counterproposal",
    artifactDigest: "7".repeat(64),
    sequence: "1",
  });
  const proposed = await signedCheckpoint({
    account: INITIATOR,
    role: "initiator",
    artifactType: "proposal",
    artifactDigest: digestHex(fixture.proposalEnvelope),
    sequence: "2",
    previousCheckpointDigest: commitmentCheckpointDigest(counterproposed),
  });
  const accepted = await signedCheckpoint({
    account: RESPONDER,
    role: "responder",
    artifactType: "acceptance",
    artifactDigest: digestHex(fixture.acceptanceEnvelope),
    sequence: "3",
    previousCheckpointDigest: commitmentCheckpointDigest(proposed),
  });
  return [counterproposed, proposed, accepted];
}

function authorizationInput(fixture) {
  return {
    acceptanceEnvelope: fixture.acceptanceEnvelope,
    descriptorEnvelope: fixture.descriptorEnvelope,
    evidence: fixture.evidence,
    expectedHostSessionKeyCertificateDigest: fixture.descriptorEnvelope.descriptor.hostSessionKeyCertificateDigest,
    expectedPublicKey: fixture.host.publicKey,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    expectedTerms: TERMS,
    nowMs: NOW_MS,
    proposalEnvelope: fixture.proposalEnvelope,
    receipts: fixture.receipts,
    resolveRegistration: async (party) => ({
      owner: party.sessionKeyAddress,
      registrationBlock: party.erc8004.registrationBlock,
    }),
    transitions: fixture.transitions,
  };
}

test("additive checkpoints verify beside the existing v2 authority chain without replacing it", async () => {
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

  const proposed = await signedCheckpoint({
    account: INITIATOR,
    role: "initiator",
    artifactType: "proposal",
    artifactDigest: digestHex(fixture.proposalEnvelope),
    sequence: "1",
  });
  const accepted = await signedCheckpoint({
    account: RESPONDER,
    role: "responder",
    artifactType: "acceptance",
    artifactDigest: digestHex(fixture.acceptanceEnvelope),
    sequence: "2",
    previousCheckpointDigest: commitmentCheckpointDigest(proposed),
  });
  const checkpoints = await verifyAgentHandshakeV2CommitmentCheckpointChain({
    checkpoints: [proposed, accepted],
    expectedSessionId: SESSION_ID,
    expectedArtifacts: [
      { role: "initiator", signerAddress: INITIATOR.address.toLowerCase(), artifactType: "proposal", artifactDigest: digestHex(fixture.proposalEnvelope) },
      { role: "responder", signerAddress: RESPONDER.address.toLowerCase(), artifactType: "acceptance", artifactDigest: digestHex(fixture.acceptanceEnvelope) },
    ],
    nowMs: NOW_MS,
  });

  assert.deepEqual(checkpoints.map((checkpoint) => checkpoint.sequence), ["1", "2"]);
  assert.equal("checkpointDigest" in fixture.transitions[0], false);
  assert.equal("checkpointDigests" in fixture.evidence.initiator.result, false);
  await verifyAgentHandshakeV2Evidence({
    envelope: fixture.evidence.initiator,
    expectedParty: fixture.parties.initiator,
    expectedPolicyDigest: fixture.parties.initiator.policyDigest,
    expectedReference: TERMS.reference,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedRole: "initiator",
    expectedSessionDigest: fixture.transitions[0].sessionDigest,
    expectedStatementDigest: fixture.transitions[0].statementDigest,
    expectedTransitionDigests: fixture.transitions.map(agentHandshakeV2TransitionDigest),
    identityPolicy: fixture.descriptorEnvelope.descriptor.identityPolicy,
  });
});

test("authorization can require additive checkpoints bound to exact existing artifacts", async () => {
  const fixture = await buildV2Fixture();
  const commitmentCheckpoints = await checkpointPair(fixture);
  await assert.doesNotReject(() => verifyAgentHandshakeV2Authorization({
    ...authorizationInput(fixture),
    commitmentCheckpoints,
    requireCommitmentCheckpoints: true,
  }));
  await assert.rejects(
    () => verifyAgentHandshakeV2Authorization({
      ...authorizationInput(fixture),
      requireCommitmentCheckpoints: true,
    }),
    /Agent handshake v2 authorization verification failed/,
    "required checkpoints absent",
  );
  const wrongProposalCheckpointPair = await checkpointPair(fixture, { proposalDigest: "8".repeat(64) });
  await assert.rejects(
    () => verifyAgentHandshakeV2Authorization({
      ...authorizationInput(fixture),
      commitmentCheckpoints: wrongProposalCheckpointPair,
      requireCommitmentCheckpoints: true,
    }),
    /Agent handshake v2 authorization verification failed/,
    "different proposal artifact",
  );
  await assert.rejects(
    () => verifyAgentHandshakeV2Authorization({
      ...authorizationInput(fixture),
      commitmentCheckpoints,
      proposalEnvelope: undefined,
      requireCommitmentCheckpoints: true,
    }),
    /Agent handshake v2 authorization verification failed/,
    "checkpoints cannot replace proposal",
  );
});

test("authorization checkpoint path allows bounded preliminary counterproposal commitments before terminal artifacts", async () => {
  const fixture = await buildV2Fixture();
  const checkpointPath = await checkpointPathWithCounterproposal(fixture);
  const wrongTerminalPath = await checkpointPathWithCounterproposal({ ...fixture, proposalEnvelope: { altered: true } });
  await assert.doesNotReject(() => verifyAgentHandshakeV2Authorization({
    ...authorizationInput(fixture),
    commitmentCheckpoints: checkpointPath,
    requireCommitmentCheckpoints: true,
  }));
  await assert.rejects(
    () => verifyAgentHandshakeV2Authorization({
      ...authorizationInput(fixture),
      commitmentCheckpoints: wrongTerminalPath,
      requireCommitmentCheckpoints: true,
    }),
    /Agent handshake v2 authorization verification failed/,
    "terminal proposal digest must bind existing proposal envelope",
  );
  await assert.rejects(
    () => verifyAgentHandshakeV2Authorization({
      ...authorizationInput(fixture),
      commitmentCheckpoints: checkpointPath,
      requireCommitmentCheckpoints: "true",
    }),
    /Agent handshake v2 authorization verification failed/,
    "required flag must be boolean",
  );
});

test("checkpoints cannot create a separate acknowledgment authority", async () => {
  const fixture = await buildV2Fixture();
  const acknowledged = await signedCheckpoint({
    account: INITIATOR,
    role: "initiator",
    artifactType: "acceptance",
    artifactDigest: digestHex(fixture.acceptanceEnvelope),
    sequence: "3",
    previousCheckpointDigest: "9".repeat(64),
  });
  await assert.rejects(
    () => verifyAgentHandshakeV2CommitmentCheckpointChain({
      checkpoints: [acknowledged],
      expectedSessionId: SESSION_ID,
      expectedArtifacts: [
        { role: "initiator", signerAddress: INITIATOR.address.toLowerCase(), artifactType: "acceptance", artifactDigest: digestHex(fixture.acceptanceEnvelope) },
      ],
      nowMs: NOW_MS,
    }),
    /Agent handshake v2 commitment checkpoint verification failed/,
  );
});
