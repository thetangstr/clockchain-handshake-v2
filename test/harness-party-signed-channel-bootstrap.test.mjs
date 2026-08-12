import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { a2aAgentCardDigest } from "../src/a2a/agent-card.mjs";
import { createA2ACardBootstrap } from "../src/a2a/card-bootstrap.mjs";
import { INVITATION_BOOTSTRAP_CARD_CAPABILITY } from "../src/a2a/invitation-bootstrap-transport.mjs";
import { initializeWallet } from "../src/core/wallet-bridge.mjs";
import { createPartyA2AAuthority } from "../src/harness/party-a2a-authority.mjs";
import { activatePartySignedChannel } from "../src/harness/party-signed-channel-bootstrap.mjs";
import { NOW_MS, REPOSITORY_SHA, SESSION_ID, TERMS, buildV2Fixture } from "./support/agent-handshake-v2-fixture.mjs";

const KEYS = Object.freeze({ initiator: `0x${"4".repeat(64)}`, responder: `0x${"5".repeat(64)}` });
const RUNTIME = Object.freeze({
  initiator: Object.freeze({ endpoint: "https://initiator.task.local:8443", runtimeId: "runtime-initiator", taskId: "task-initiator", tlsCertificateSha256: "6".repeat(64), workloadAttestationDigest: "4".repeat(64) }),
  responder: Object.freeze({ endpoint: "https://responder.task.local:8443", runtimeId: "runtime-responder", taskId: "task-responder", tlsCertificateSha256: "7".repeat(64), workloadAttestationDigest: "5".repeat(64) }),
});

function connectedCardTransports(events) {
  const receivers = { initiator: null, responder: null };
  function transport(role) {
    const peer = role === "initiator" ? "responder" : "initiator";
    return Object.freeze({
      [INVITATION_BOOTSTRAP_CARD_CAPABILITY]: Object.freeze({
        registerReceiver(receiver) { receivers[role] = receiver; },
        async sendCard(input) {
          events.push(input.artifactKind);
          const artifactDigest = await receivers[peer](input);
          return { acknowledged: true, artifactDigest };
        },
        retire() { receivers[role] = null; },
      }),
    });
  }
  return { initiator: transport("initiator"), responder: transport("responder") };
}

function cardBinding(binding) {
  return {
    endpoint: binding.runtime.endpoint,
    partySignerAddress: binding.partySignerAddress,
    runtimeId: binding.runtime.runtimeId,
    taskId: binding.runtime.taskId,
    workloadAttestationDigest: binding.runtime.workloadAttestationDigest,
  };
}

test("party signed channel activation performs responder-first card exchange after signer creation", async (t) => {
  const fixture = await buildV2Fixture();
  const root = await mkdtemp(join(tmpdir(), "party-signed-channel-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const events = [];
  const cardTransports = connectedCardTransports(events);
  const authorities = {};
  for (const role of ["initiator", "responder"]) {
    const statePath = join(root, role, "wallet.json");
    await initializeWallet({ statePath, platform: "darwin", generatePrivateKey: () => KEYS[role] });
    authorities[role] = await createPartyA2AAuthority({
      nowMs: () => NOW_MS,
      peerRuntime: RUNTIME[role === "initiator" ? "responder" : "initiator"],
      platform: "darwin",
      policyDigest: fixture.parties[role].policyDigest,
      repositorySha: REPOSITORY_SHA,
      role,
      runtime: RUNTIME[role],
      sessionId: SESSION_ID,
      statePath,
      terms: TERMS,
    });
  }
  const activations = Object.fromEntries(["initiator", "responder"].map((role) => [role, activatePartySignedChannel({
    createAuthority: async () => authorities[role],
    createCardBootstrap: async ({ authorityBinding }) => createA2ACardBootstrap({
      role,
      sessionId: SESSION_ID,
      nowMs: () => NOW_MS,
      ownBinding: cardBinding(authorityBinding),
      peerBinding: cardBinding(authorities[role === "initiator" ? "responder" : "initiator"].publicBinding()),
      transport: cardTransports[role],
    }),
    createTaskTransport: async ({ cards }) => Object.freeze({
      async close() {},
      publicEvidence() { return { messages: [] }; },
      async receive() { return null; },
      async sendEnvelope() { throw new Error("not used"); },
      cardDigests: { initiator: a2aAgentCardDigest(cards.initiator), responder: a2aAgentCardDigest(cards.responder) },
    }),
    nowMs: () => NOW_MS,
    role,
    sessionId: SESSION_ID,
    sleep: async () => new Promise((resolve) => setImmediate(resolve)),
  })]));
  const [initiator, responder] = await Promise.all([activations.initiator, activations.responder]);
  assert.deepEqual(events, ["responder_card", "initiator_card"]);
  assert.equal(a2aAgentCardDigest(initiator.cards.initiator), a2aAgentCardDigest(responder.cards.initiator));
  assert.equal(a2aAgentCardDigest(initiator.cards.responder), a2aAgentCardDigest(responder.cards.responder));
  assert.equal(initiator.authority, authorities.initiator);
  assert.equal(responder.authority, authorities.responder);
});
