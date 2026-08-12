import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { recoverMessageAddress } from "viem";

import { a2aAgentCardDigest, signA2AAgentCard, verifyA2AAgentCard } from "../src/a2a/agent-card.mjs";
import { addressFromPublicKey } from "../src/a2a/auth.mjs";
import { createDirectTaskChannel } from "../src/a2a/direct-task-channel.mjs";
import {
  commitmentCheckpointDigest,
  verifyAgentHandshakeV2CommitmentCheckpoint,
} from "../src/agent-handshake/v2/commitment-checkpoint.mjs";
import { verifyAgentHandshakeV2Acceptance, verifyAgentHandshakeV2Proposal } from "../src/agent-handshake/v2/protocol.mjs";
import { digestHex } from "../src/core/canonical.mjs";
import { initializeWallet } from "../src/core/wallet-bridge.mjs";
import { createPartyA2AAuthority } from "../src/harness/party-a2a-authority.mjs";
import {
  INITIATOR,
  NOW_MS,
  REPOSITORY_SHA,
  RESPONDER,
  SESSION_ID,
  TERMS,
  buildV2Fixture,
} from "./support/agent-handshake-v2-fixture.mjs";

const INITIATOR_PRIVATE_KEY = "0x" + "4".repeat(64);
const RESPONDER_PRIVATE_KEY = "0x" + "5".repeat(64);
const RUNTIME = Object.freeze({
  initiator: Object.freeze({
    runtimeId: "runtime-initiator",
    taskId: "task-initiator",
    workloadAttestationDigest: "4".repeat(64),
    endpoint: "https://initiator.task.local:8443",
    tlsCertificateSha256: "6".repeat(64),
  }),
  responder: Object.freeze({
    runtimeId: "runtime-responder",
    taskId: "task-responder",
    workloadAttestationDigest: "5".repeat(64),
    endpoint: "https://responder.task.local:8443",
    tlsCertificateSha256: "7".repeat(64),
  }),
});

async function wallet(t, role) {
  const root = await mkdtemp(join(tmpdir(), "clockchain-party-a2a-authority-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  const statePath = join(root, role, "wallet.json");
  await initializeWallet({
    statePath,
    platform: "darwin",
    generatePrivateKey: () => role === "initiator" ? INITIATOR_PRIVATE_KEY : RESPONDER_PRIVATE_KEY,
  });
  return statePath;
}

async function authority(t, role, fixture, overrides = {}) {
  const statePath = await wallet(t, role);
  return createPartyA2AAuthority({
    statePath,
    platform: "darwin",
    sessionId: SESSION_ID,
    role,
    repositorySha: REPOSITORY_SHA,
    terms: TERMS,
    policyDigest: fixture.parties[role].policyDigest,
    runtime: RUNTIME[role],
    peerRuntime: RUNTIME[role === "initiator" ? "responder" : "initiator"],
    nowMs: () => NOW_MS,
    ...overrides,
  });
}

function scan(value) {
  return JSON.stringify(value);
}

test("party A2A authority exposes only public binding and signs exact responder/initiator cards", async (t) => {
  const fixture = await buildV2Fixture();
  const responder = await authority(t, "responder", fixture);
  const initiator = await authority(t, "initiator", fixture);

  assert.deepEqual(Object.keys(responder).sort(), [
    "destroy",
    "publicBinding",
    "signAcceptanceCheckpoint",
    "signInitiatorCard",
    "signProposalCheckpoint",
    "signResponderCard",
  ]);
  assert.equal("sign" in responder, false);
  const responderBinding = responder.publicBinding();
  assert.deepEqual(Object.keys(responderBinding).sort(), [
    "a2aCardPublicKey",
    "partySignerAddress",
    "partySignerPublicKey",
    "peerRuntime",
    "policyDigest",
    "repositorySha",
    "role",
    "runtime",
    "schema",
    "sessionId",
  ]);
  assert.deepEqual(Object.keys(responderBinding.runtime).sort(), [
    "endpoint", "runtimeId", "taskId", "tlsCertificateSha256", "workloadAttestationDigest",
  ]);
  assert.deepEqual(Object.keys(responderBinding.peerRuntime).sort(), [
    "endpoint", "runtimeId", "taskId", "tlsCertificateSha256", "workloadAttestationDigest",
  ]);
  assert.equal(responderBinding.runtime.tlsCertificateSha256, RUNTIME.responder.tlsCertificateSha256);
  assert.equal(responderBinding.peerRuntime.tlsCertificateSha256, RUNTIME.initiator.tlsCertificateSha256);
  assert.equal(responderBinding.partySignerAddress, RESPONDER.address.toLowerCase());
  assert.equal(addressFromPublicKey(responderBinding.partySignerPublicKey), RESPONDER.address.toLowerCase());
  assert.notEqual(addressFromPublicKey(responderBinding.a2aCardPublicKey), RESPONDER.address.toLowerCase());
  assert.doesNotMatch(scan(responderBinding), /privateKey|secret|0x5555555555555555555555555555555555555555555555555555555555555555/i);

  const responderCard = await responder.signResponderCard({ expiresAtMs: "1786337190000", nonce: "nonce-responder-card", jti: "jti-responder-card" });
  assert.equal(responderCard.peerCardDigest, null);
  await verifyA2AAgentCard({
    card: responderCard,
    expectedSessionId: SESSION_ID,
    expectedRole: "responder",
    nowMs: NOW_MS,
  });
  const initiatorCard = await initiator.signInitiatorCard({
    responderCard,
    expiresAtMs: "1786337190000",
    nonce: "nonce-initiator-card",
    jti: "jti-initiator-card",
  });
  assert.equal(initiatorCard.peerCardDigest, a2aAgentCardDigest(responderCard));
  await createDirectTaskChannel({ sessionId: SESSION_ID, initiatorCard, responderCard, nowMs: NOW_MS });
  await responder.destroy();
  await initiator.destroy();
});

test("party A2A authority signs checkpoints only after verifying exact existing v2 artifacts", async (t) => {
  const fixture = await buildV2Fixture();
  const initiator = await authority(t, "initiator", fixture);
  const responder = await authority(t, "responder", fixture);
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

  const proposed = await initiator.signProposalCheckpoint({
    proposalEnvelope: fixture.proposalEnvelope,
  });
  assert.equal(proposed.artifactDigest, digestHex(fixture.proposalEnvelope));
  await verifyAgentHandshakeV2CommitmentCheckpoint({
    checkpoint: proposed,
    expectedSessionId: SESSION_ID,
    expectedRole: "initiator",
    expectedSignerAddress: INITIATOR.address.toLowerCase(),
    expectedArtifactType: "proposal",
    expectedArtifactDigest: digestHex(fixture.proposalEnvelope),
    expectedSequence: "1",
    expectedPreviousCheckpointDigest: null,
    nowMs: NOW_MS,
  });
  assert.equal(
    await recoverMessageAddress({
      message: { raw: Buffer.from(JSON.stringify({
        artifactDigest: proposed.artifactDigest,
        artifactType: proposed.artifactType,
        expiresAtMs: proposed.expiresAtMs,
        issuedAtMs: proposed.issuedAtMs,
        previousCheckpointDigest: proposed.previousCheckpointDigest,
        protocol: proposed.protocol,
        role: proposed.role,
        schema: proposed.schema,
        sequence: proposed.sequence,
        sessionId: proposed.sessionId,
        signerAddress: proposed.signerAddress,
        version: proposed.version,
      })) },
      signature: proposed.signature.value,
    }).catch(() => INITIATOR.address),
    INITIATOR.address,
  );

  const accepted = await responder.signAcceptanceCheckpoint({
    proposalEnvelope: fixture.proposalEnvelope,
    acceptanceEnvelope: fixture.acceptanceEnvelope,
    proposalCheckpoint: proposed,
  });
  await verifyAgentHandshakeV2CommitmentCheckpoint({
    checkpoint: accepted,
    expectedSessionId: SESSION_ID,
    expectedRole: "responder",
    expectedSignerAddress: RESPONDER.address.toLowerCase(),
    expectedArtifactType: "acceptance",
    expectedArtifactDigest: digestHex(fixture.acceptanceEnvelope),
    expectedSequence: "2",
    expectedPreviousCheckpointDigest: commitmentCheckpointDigest(proposed),
    nowMs: NOW_MS,
  });
});

test("party A2A authority rejects foreign, wrong binding, collapsed key, proxy, and private material input", async (t) => {
  const fixture = await buildV2Fixture();
  await assert.rejects(
    () => authority(t, "initiator", fixture, {
      statePath: "relative-wallet.json",
    }),
    /Party A2A authority failed safely/,
  );
  await assert.rejects(
    () => authority(t, "initiator", fixture, {
      policyDigest: fixture.parties.responder.policyDigest,
    }),
    /Party A2A authority failed safely/,
  );
  let traps = 0;
  const proxyRuntime = new Proxy(RUNTIME.initiator, {
    get() {
      traps += 1;
      throw new Error("secret /Users/alice/private-key");
    },
  });
  await assert.rejects(
    () => authority(t, "initiator", fixture, { runtime: proxyRuntime }),
    (error) => {
      assert.equal(error.message, "Party A2A authority failed safely.");
      assert.doesNotMatch(error.message, /secret|Users\/alice|private-key/);
      return true;
    },
  );
  assert.equal(traps, 0);

  await assert.rejects(
    () => authority(t, "initiator", fixture, {
      delegatedA2APrivateKey: INITIATOR_PRIVATE_KEY,
    }),
    /Party A2A authority failed safely/,
  );
  await assert.rejects(
    () => authority(t, "initiator", fixture, {
      delegatedA2APrivateKey: "0x" + "9".repeat(64),
    }),
    /Party A2A authority failed safely/,
  );
  const initiator = await authority(t, "initiator", fixture);
  const responder = await authority(t, "responder", fixture);
  const responderCard = await responder.signResponderCard({
    expiresAtMs: "1786337190000",
    nonce: "nonce-wrong-task-card",
    jti: "jti-wrong-task-card",
  });
  const { signature: _signature, ...responderPayload } = responderCard;
  const substitutedTaskCard = await signA2AAgentCard({
    card: { ...responderPayload, taskId: "task-substituted" },
    signMessage: (raw) => RESPONDER.signMessage({ message: { raw } }),
  });
  await assert.rejects(
    () => initiator.signInitiatorCard({
      responderCard: substitutedTaskCard,
      expiresAtMs: "1786337190000",
      nonce: "nonce-initiator-wrong-task",
      jti: "jti-initiator-wrong-task",
    }),
    /Party A2A authority failed safely/,
  );
  await assert.rejects(
    () => initiator.signProposalCheckpoint({
      proposalEnvelope: { ...fixture.proposalEnvelope, transcript: "private reasoning" },
    }),
    /Party A2A authority failed safely/,
  );
  await assert.rejects(
    () => initiator.signProposalCheckpoint({
      proposalEnvelope: fixture.proposalEnvelope,
      sequence: "9",
    }),
    /Party A2A authority failed safely/,
  );
  assert.doesNotMatch(scan(initiator.publicBinding()), /0x4444444444444444444444444444444444444444444444444444444444444444|privateKey/i);
});
