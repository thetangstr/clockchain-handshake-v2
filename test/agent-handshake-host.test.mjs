import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

import {
  AGENT_HANDSHAKE_HOST_ROLES,
  runAgentHandshakeHostSession,
} from "../src/agent-handshake/host.mjs";
import {
  INITIATOR,
  NOW_MS,
  REPOSITORY_SHA,
  RESPONDER,
  SESSION_ID,
  TERMS,
  buildAgentHandshakeFixture,
} from "./support/agent-handshake-fixture.mjs";
import {
  AGENT_HANDSHAKE_PARTY_RESULT_SCHEMA,
  signAgentHandshakeEvidence,
} from "../src/agent-handshake/evidence.mjs";
import { agentTransitionDigest } from "../src/agent-handshake/protocol.mjs";

test("host source never signs either stakeholder artifact", async () => {
  const source = await readFile(new URL("../src/agent-handshake/host.mjs", import.meta.url), "utf8");
  assert.equal(source.includes("signAgentHandshakeProposal"), false);
  assert.equal(source.includes("signAgentHandshakeAcceptance"), false);
  assert.match(source, /roles:\s*\["initiator",\s*"responder"\]/);
  assert.match(source, /verifyAgentHandshakeAuthorization/);
  assert.deepEqual(AGENT_HANDSHAKE_HOST_ROLES, ["initiator", "responder"]);
});

test("host entry point preserves v1 by default and dispatches v2 explicitly", async () => {
  const source = await readFile(
    new URL("../bin/agent-handshake-host.mjs", import.meta.url),
    "utf8",
  );
  assert.match(source, /AGENT_HANDSHAKE_PROTOCOL/);
  assert.match(source, /clockchain\.agent-handshake\/v2/);
  assert.match(source, /agent-handshake\/v2\/production-adapter\.mjs/);
  assert.match(source, /runAgentHandshakeV2HostSession/);
  assert.match(source, /runAgentHandshakeHostSession/);
});

test("host funds exact seats, observes both signatures, checks evidence, and certifies", async () => {
  const fixture = await buildAgentHandshakeFixture();
  const evidence = {};
  for (const [role, account] of [["initiator", INITIATOR], ["responder", RESPONDER]]) {
    evidence[role] = await signAgentHandshakeEvidence({
      result: {
        externalActionPerformed: false,
        party: fixture[role],
        reference: TERMS.reference,
        repositorySha: REPOSITORY_SHA,
        role,
        schema: AGENT_HANDSHAKE_PARTY_RESULT_SCHEMA,
        sessionDigest: fixture.base.sessionDigest,
        statementDigest: fixture.base.statementDigest,
        transitionDigests: fixture.transitions.map(agentTransitionDigest),
      },
      signMessage: (bytes) => account.signMessage({ message: { raw: bytes } }),
    });
  }
  const calls = [];
  const ports = {
    announceParties: async (value) => calls.push(["parties", value]),
    awaitAcceptance: async () => fixture.acceptanceEnvelope,
    awaitAnchors: async () => ({ receipts: fixture.receipts, transitions: fixture.transitions }),
    awaitEvidence: async (role) => evidence[role],
    awaitIdentity: async (role) => ({ address: fixture[role].address }),
    awaitPartyReady: async (role) => fixture[role],
    awaitProposal: async () => fixture.proposalEnvelope,
    fundIdentity: async (value) => calls.push(["fund", value]),
    publishDescriptor: async (value) => calls.push(["descriptor", value]),
    publishResult: async (value) => calls.push(["result", value]),
    publishSnapshot: async (value) => calls.push(["snapshot", value.currentStage]),
    resolveOwner: async (agentId) => fixture[agentId === "9452" ? "initiator" : "responder"].address,
  };
  const outcome = await runAgentHandshakeHostSession({
    now: () => NOW_MS,
    ports,
    session: {
      expectedPublicKey: fixture.host.publicKey,
      keyId: fixture.host.keyId,
      privateKeyPem: fixture.host.privateKeyPem,
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
      terms: TERMS,
    },
  });
  assert.equal(outcome.certificate.result.outcome, "VERIFIED");
  assert.deepEqual(
    calls.filter(([kind]) => kind === "fund").map(([, value]) => value),
    [
      { address: fixture.initiator.address, role: "initiator" },
      { address: fixture.responder.address, role: "responder" },
    ],
  );
  assert.equal(calls.filter(([kind]) => kind === "descriptor").length, 1);
  assert.equal(calls.filter(([kind]) => kind === "result").length, 1);
  assert.equal(calls.at(-1)[1], "CERTIFIED");
});
