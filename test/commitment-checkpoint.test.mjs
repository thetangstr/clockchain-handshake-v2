import assert from "node:assert/strict";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import { digestHex } from "../src/core/canonical.mjs";
import {
  AGENT_HANDSHAKE_V2_COMMITMENT_CHECKPOINT_SCHEMA,
  commitmentCheckpointDigest,
  signAgentHandshakeV2CommitmentCheckpoint,
  verifyAgentHandshakeV2CommitmentCheckpoint,
  verifyAgentHandshakeV2CommitmentCheckpointChain,
} from "../src/agent-handshake/v2/commitment-checkpoint.mjs";
import {
  INITIATOR,
  NOW_MS,
  RESPONDER,
  SESSION_ID,
  buildV2Fixture,
} from "./support/agent-handshake-v2-fixture.mjs";

const DIRECTOR = privateKeyToAccount(`0x${"3".repeat(64)}`);

async function checkpoint({ account, role, artifactType, artifactDigest, sequence, previousCheckpointDigest = null, version = "1" }) {
  return signAgentHandshakeV2CommitmentCheckpoint({
    checkpoint: {
      schema: AGENT_HANDSHAKE_V2_COMMITMENT_CHECKPOINT_SCHEMA,
      version,
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

test("relay-bound commitment checkpoints use the canonical decimal-string version", async () => {
  const fixture = await buildV2Fixture();
  const proposed = await checkpoint({
    account: INITIATOR,
    role: "initiator",
    artifactType: "proposal",
    artifactDigest: digestHex(fixture.proposalEnvelope),
    sequence: "1",
    version: "1",
  });

  assert.equal(proposed.version, "1");
  await assert.rejects(
    () => checkpoint({
      account: INITIATOR,
      role: "initiator",
      artifactType: "proposal",
      artifactDigest: digestHex(fixture.proposalEnvelope),
      sequence: "1",
      version: 1,
    }),
    /Agent handshake v2 commitment checkpoint verification failed/,
  );
});

test("commitment checkpoints form an additive party-signed canonical chain", async () => {
  const fixture = await buildV2Fixture();
  const proposed = await checkpoint({
    account: INITIATOR,
    role: "initiator",
    artifactType: "proposal",
    artifactDigest: digestHex(fixture.proposalEnvelope),
    sequence: "1",
  });
  const accepted = await checkpoint({
    account: RESPONDER,
    role: "responder",
    artifactType: "acceptance",
    artifactDigest: digestHex(fixture.acceptanceEnvelope),
    sequence: "2",
    previousCheckpointDigest: commitmentCheckpointDigest(proposed),
  });

  const verified = await verifyAgentHandshakeV2CommitmentCheckpointChain({
    checkpoints: [proposed, accepted],
    expectedSessionId: SESSION_ID,
    expectedArtifacts: [
      { role: "initiator", signerAddress: INITIATOR.address.toLowerCase(), artifactType: "proposal", artifactDigest: digestHex(fixture.proposalEnvelope) },
      { role: "responder", signerAddress: RESPONDER.address.toLowerCase(), artifactType: "acceptance", artifactDigest: digestHex(fixture.acceptanceEnvelope) },
    ],
    nowMs: NOW_MS,
  });

  assert.equal(verified.length, 2);
  assert.equal(verified[1].previousCheckpointDigest, commitmentCheckpointDigest(verified[0]));
});

test("commitment checkpoints reject foreign authors, digest drift, broken chain, expiry, and extras", async () => {
  const fixture = await buildV2Fixture();
  const proposed = await checkpoint({
    account: INITIATOR,
    role: "initiator",
    artifactType: "proposal",
    artifactDigest: digestHex(fixture.proposalEnvelope),
    sequence: "1",
  });
  const director = await checkpoint({
    account: DIRECTOR,
    role: "initiator",
    artifactType: "proposal",
    artifactDigest: digestHex(fixture.proposalEnvelope),
    sequence: "1",
  });
  const accepted = await checkpoint({
    account: RESPONDER,
    role: "responder",
    artifactType: "acceptance",
    artifactDigest: digestHex(fixture.acceptanceEnvelope),
    sequence: "2",
    previousCheckpointDigest: "9".repeat(64),
  });

  await assert.rejects(
    () => verifyAgentHandshakeV2CommitmentCheckpoint({
      checkpoint: director,
      expectedSessionId: SESSION_ID,
      expectedRole: "initiator",
      expectedSignerAddress: INITIATOR.address.toLowerCase(),
      expectedArtifactType: "proposal",
      expectedArtifactDigest: digestHex(fixture.proposalEnvelope),
      expectedSequence: "1",
      expectedPreviousCheckpointDigest: null,
      nowMs: NOW_MS,
    }),
    /Agent handshake v2 commitment checkpoint verification failed/,
    "director-authored proposal",
  );
  for (const [name, bad] of [
    ["changed artifact digest", { ...proposed, artifactDigest: "8".repeat(64) }],
    ["extra raw transcript", { ...proposed, transcript: "private reasoning" }],
  ]) {
    await assert.rejects(
      () => verifyAgentHandshakeV2CommitmentCheckpoint({
        checkpoint: bad,
        expectedSessionId: SESSION_ID,
        expectedRole: "initiator",
        expectedSignerAddress: INITIATOR.address.toLowerCase(),
        expectedArtifactType: "proposal",
        expectedArtifactDigest: digestHex(fixture.proposalEnvelope),
        expectedSequence: "1",
        expectedPreviousCheckpointDigest: null,
        nowMs: NOW_MS,
      }),
      /Agent handshake v2 commitment checkpoint verification failed/,
      name,
    );
  }
  await assert.rejects(
    () => verifyAgentHandshakeV2CommitmentCheckpointChain({
      checkpoints: [proposed, accepted],
      expectedSessionId: SESSION_ID,
      expectedArtifacts: [
        { role: "initiator", signerAddress: INITIATOR.address.toLowerCase(), artifactType: "proposal", artifactDigest: digestHex(fixture.proposalEnvelope) },
        { role: "responder", signerAddress: RESPONDER.address.toLowerCase(), artifactType: "acceptance", artifactDigest: digestHex(fixture.acceptanceEnvelope) },
      ],
      nowMs: NOW_MS,
    }),
    /Agent handshake v2 commitment checkpoint verification failed/,
    "broken previous checkpoint",
  );
  await assert.rejects(
    () => verifyAgentHandshakeV2CommitmentCheckpoint({
      checkpoint: proposed,
      expectedSessionId: SESSION_ID,
      expectedRole: "initiator",
      expectedSignerAddress: INITIATOR.address.toLowerCase(),
      expectedArtifactType: "proposal",
      expectedArtifactDigest: digestHex(fixture.proposalEnvelope),
      expectedSequence: "1",
      expectedPreviousCheckpointDigest: null,
      nowMs: 1786337190000,
    }),
    /Agent handshake v2 commitment checkpoint verification failed/,
    "expired",
  );
});
