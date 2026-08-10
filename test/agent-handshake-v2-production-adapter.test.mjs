import assert from "node:assert/strict";
import test from "node:test";

import {
  createAgentHandshakeV2HostPorts,
  loadAgentHandshakeV2Session,
} from "../src/agent-handshake/v2/production-adapter.mjs";
import { verifyHostSessionKeyCertificate, ed25519PublicKeyFingerprint } from "../src/agent-handshake/v2/host-key-certificate.mjs";
import { ed25519 } from "./support/agent-handshake-v2-fixture.mjs";

test("production session publishes a root-signed host key before discovery with independent clocks", async () => {
  const root = ed25519("root-2026-08");
  const calls = [];
  const now = 1_786_337_000_000;
  const session = await loadAgentHandshakeV2Session({
    env: { HANDSHAKE_SHA: "d".repeat(40) },
    loadRoot: async () => root,
    now: () => now,
    publicClient: { getBlockNumber: async () => 6999n },
    relayClient: { createSession: async (input) => calls.push(input) },
  });
  assert.equal(session.protocol, "clockchain.agent-handshake/v2");
  assert.equal(session.sessionDeadlineMs, now + 10 * 60_000);
  assert.equal(session.invitationExpiresAtMs, now + 120_000);
  assert.equal(session.terms.validForSeconds, "90");
  assert.equal(session.sessionOpenedBlock, "6999");
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].discovery.hostSessionKeyCertificate, session.hostSessionKeyCertificate);
  verifyHostSessionKeyCertificate(session.hostSessionKeyCertificate, {
    expectedRepositorySha: session.repositorySha,
    expectedSessionId: session.sessionId,
    nowMs: now,
    rootKeyRing: [{
      kid: root.keyId,
      publicKey: root.publicKey,
      fingerprint: ed25519PublicKeyFingerprint(root.publicKey),
    }],
    sessionDeadlineMs: session.sessionDeadlineMs,
  });
});

test("production ports map only role-tagged v2 messages and reserve before funding", async () => {
  const seen = [];
  const messages = {
    agent_v2_identity_claim: { body: { sessionKeyAddress: "0x" + "1".repeat(40), policyDigest: "a".repeat(64) } },
    agent_v2_party_ready: { body: { ok: "party" } },
    agent_v2_proposal: { body: { proposalEnvelope: { ok: "proposal" } } },
    agent_v2_acceptance: { body: { acceptanceEnvelope: { ok: "acceptance" } } },
    agent_v2_evidence: { body: { evidenceEnvelope: { ok: "evidence" } } },
    agent_v2_anchor_report: { body: { transitions: [{}, {}, {}] } },
  };
  const ports = await createAgentHandshakeV2HostPorts({
    relayUrl: "https://relay.test",
    sessionDeadlineMs: Date.now() + 60_000,
    sessionId: "22222222-3333-4444-8555-666666666666",
  }, {
    fundingBudget: { reserve: async (input) => seen.push(["reserve", input]) },
    fundIdentity: async (input) => seen.push(["fund", input]),
    postHostMessage: async (kind, body) => seen.push([kind, body]),
    publicClient: {},
    relayClient: { generateEnvelopeKeyPair: () => ({}) },
    waitForMessage: async (kind, role) => {
      seen.push(["wait", kind, role]);
      return messages[kind];
    },
  });
  assert.equal((await ports.awaitIdentityClaim("initiator")).policyDigest, "a".repeat(64));
  assert.deepEqual(await ports.awaitProposal(), { ok: "proposal" });
  await ports.reserveFunding({
    addresses: ["0x" + "1".repeat(40), "0x" + "2".repeat(40)],
    identityMode: "required_fresh",
    sessionId: "22222222-3333-4444-8555-666666666666",
  });
  await ports.fundIdentity({ address: "0x" + "1".repeat(40), role: "initiator" });
  assert.deepEqual(seen.slice(-2).map(([kind]) => kind), ["reserve", "fund"]);
});
