import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  createAgentHandshakeHostPorts,
  loadAgentHandshakeSession,
} from "../src/agent-handshake/production-adapter.mjs";
import { buildAgentHandshakeFixture, SESSION_ID } from "./support/agent-handshake-fixture.mjs";

test("generic host defaults to the built-in production adapter", async () => {
  const source = await readFile(new URL("../bin/agent-handshake-host.mjs", import.meta.url), "utf8");
  assert.match(source, /production-adapter\.mjs/);
  assert.doesNotMatch(source, /AGENT_HANDSHAKE_HOST_ADAPTER is required/);
});

test("generic production session fails closed without an immutable repository SHA", async () => {
  await assert.rejects(
    loadAgentHandshakeSession({ env: {} }),
    /HANDSHAKE_SHA_INVALID/,
  );
});

test("production session publishes generic discovery with the immutable kit revision", async () => {
  const calls = [];
  const session = await loadAgentHandshakeSession({
    env: {
      HANDSHAKE_RELAY: "https://relay.example.test",
      HANDSHAKE_SHA: "d".repeat(40),
    },
    now: () => 1786337000000,
    relayClient: { createSession: async (value) => calls.push(value) },
  });
  assert.equal(session.repositorySha, "d".repeat(40));
  assert.equal(session.terms.statement, "Two stakeholder agents may communicate about shipment NS-1847.");
  assert.equal(calls[0].discovery.operatorPublicKey, session.expectedPublicKey);
  assert.equal(calls[0].discovery.expiresAtMs, String(1786337000000 + 45 * 60_000));
  assert.equal(calls[0].discovery.relayUrl, "https://relay.example.test");
});

test("production adapter maps the generic relay messages without authoring a party artifact", async () => {
  const fixture = await buildAgentHandshakeFixture();
  const calls = [];
  const messages = {
    "identity_ready:initiator": { body: { address: fixture.initiator.address } },
    "identity_ready:responder": { body: { address: fixture.responder.address } },
    "party_ready:initiator": { body: fixture.initiator },
    "party_ready:responder": { body: fixture.responder },
    "agent_proposal:initiator": { body: { proposalEnvelope: fixture.proposalEnvelope } },
    "agent_acceptance:responder": { body: { acceptanceEnvelope: fixture.acceptanceEnvelope } },
    "agent_anchor_report:initiator": {
      body: {
        transitions: fixture.transitions.map((message, index) => ({
          blockTimeRaw: fixture.receipts[index].blockTimeRaw,
          digest: fixture.receipts[index].digest,
          message,
          onChain: {
            blockHeight: fixture.receipts[index].blockHeight,
            ledgerId: fixture.receipts[index].ledgerId,
          },
        })),
      },
    },
    "agent_evidence:initiator": { body: { evidenceEnvelope: { role: "initiator" } } },
    "agent_evidence:responder": { body: { evidenceEnvelope: { role: "responder" } } },
  };
  const ports = await createAgentHandshakeHostPorts({
    expectedPublicKey: fixture.host.publicKey,
    sessionId: SESSION_ID,
  }, {
    fundSeat: async (value) => calls.push(["fund", value]),
    postHostMessage: async (kind, body) => calls.push([kind, body]),
    putResult: async (value) => calls.push(["result", value]),
    putSnapshot: async (value) => calls.push(["snapshot", value]),
    resolveOwner: async (agentId) => agentId === fixture.initiator.agentId ? fixture.initiator.address : fixture.responder.address,
    waitForMessage: async (kind, role) => messages[`${kind}:${role}`],
  });

  assert.deepEqual(await ports.awaitIdentity("initiator"), { address: fixture.initiator.address });
  await ports.fundIdentity({ address: fixture.initiator.address, role: "initiator" });
  assert.deepEqual(await ports.awaitPartyReady("responder"), fixture.responder);
  assert.deepEqual(await ports.awaitProposal(), fixture.proposalEnvelope);
  assert.deepEqual(await ports.awaitAcceptance(), fixture.acceptanceEnvelope);
  await ports.publishDescriptor(fixture.descriptorEnvelope);
  const anchors = await ports.awaitAnchors();
  assert.deepEqual(anchors.transitions, fixture.transitions);
  assert.deepEqual(anchors.receipts, fixture.receipts);
  assert.deepEqual(await ports.awaitEvidence("initiator"), { role: "initiator" });
  await ports.publishSnapshot({ schema: "clockchain.agent-handshake-snapshot/v1" });
  await ports.publishResult({ result: { schema: "clockchain.agent-handshake-result/v1" } });
  assert.equal(await ports.resolveOwner(fixture.initiator.agentId), fixture.initiator.address);
  assert.equal(calls.filter(([kind]) => kind === "fund").length, 1);
  assert.equal(calls.filter(([kind]) => kind === "agent_handshake_required").length, 1);
  const source = await readFile(new URL("../src/agent-handshake/production-adapter.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /signAgentHandshakeProposal|signAgentHandshakeAcceptance/);
});
