import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { agentTransitionDigest } from "../src/agent-handshake/protocol.mjs";
import {
  AGENT_HANDSHAKE_PARTY_RESULT_SCHEMA,
  signAgentHandshakeEvidence,
} from "../src/agent-handshake/evidence.mjs";
import { verifyAgentHandshakeAuthorization } from "../src/agent-handshake/verdict.mjs";
import {
  AgentHandshakeResultError,
  buildAgentHandshakeResult,
  verifyAgentHandshakeResult,
} from "../src/agent-handshake/result.mjs";
import {
  INITIATOR,
  NOW_MS,
  REPOSITORY_SHA,
  RESPONDER,
  SESSION_ID,
  TERMS,
  buildAgentHandshakeFixture,
  createHost,
} from "./support/agent-handshake-fixture.mjs";

const execFileAsync = promisify(execFile);

async function completed() {
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
  const verdict = await verifyAgentHandshakeAuthorization({
    acceptanceEnvelope: fixture.acceptanceEnvelope,
    descriptorEnvelope: fixture.descriptorEnvelope,
    evidence,
    expectedPublicKey: fixture.host.publicKey,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    expectedTerms: TERMS,
    nowMs: NOW_MS,
    proposalEnvelope: fixture.proposalEnvelope,
    receipts: fixture.receipts,
    resolveOwner: async (agentId) => fixture[agentId === "9452" ? "initiator" : "responder"].address,
    transitions: fixture.transitions,
  });
  const envelope = buildAgentHandshakeResult({
    issuedAtMs: "1786337220000",
    keyId: fixture.host.keyId,
    parties: { initiator: fixture.initiator, responder: fixture.responder },
    privateKeyPem: fixture.host.privateKeyPem,
    sessionId: SESSION_ID,
    verdict,
  });
  return { envelope, fixture, verdict };
}

test("both roles verify the same host-signed generic certificate", async () => {
  const { envelope, fixture } = await completed();
  for (const role of ["initiator", "responder"]) {
    const proof = verifyAgentHandshakeResult(envelope, {
      expectedParty: fixture[role],
      expectedPublicKey: fixture.host.publicKey,
      expectedRole: role,
      expectedSessionId: SESSION_ID,
    });
    assert.equal(proof.outcome, "VERIFIED");
    assert.equal(proof.externalActionPerformed, false);
  }
});

test("a validly signed certificate from another host or session is rejected", async () => {
  const { envelope, fixture, verdict } = await completed();
  const foreign = createHost("foreign-host");
  const foreignEnvelope = buildAgentHandshakeResult({
    issuedAtMs: "1786337220000",
    keyId: foreign.keyId,
    parties: { initiator: fixture.initiator, responder: fixture.responder },
    privateKeyPem: foreign.privateKeyPem,
    sessionId: SESSION_ID,
    verdict,
  });
  for (const [candidate, options] of [
    [foreignEnvelope, { expectedPublicKey: fixture.host.publicKey, expectedSessionId: SESSION_ID }],
    [envelope, { expectedPublicKey: fixture.host.publicKey, expectedSessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }],
  ]) {
    assert.throws(
      () => verifyAgentHandshakeResult(candidate, {
        expectedParty: fixture.initiator,
        expectedRole: "initiator",
        ...options,
      }),
      (error) => error instanceof AgentHandshakeResultError,
    );
  }
});

test("a signed negative outcome cannot produce terminal proof", async () => {
  const { fixture, verdict } = await completed();
  const envelope = buildAgentHandshakeResult({
    issuedAtMs: "1786337220000",
    keyId: fixture.host.keyId,
    parties: { initiator: fixture.initiator, responder: fixture.responder },
    privateKeyPem: fixture.host.privateKeyPem,
    sessionId: SESSION_ID,
    verdict: { ...verdict, outcome: "FAILED" },
  });
  assert.throws(
    () => verifyAgentHandshakeResult(envelope, {
      expectedParty: fixture.initiator,
      expectedPublicKey: fixture.host.publicKey,
      expectedRole: "initiator",
      expectedSessionId: SESSION_ID,
    }),
    (error) => error instanceof AgentHandshakeResultError,
  );
});

test("proof CLI emits a compact public result only after full verification", async () => {
  const { envelope, fixture } = await completed();
  const directory = await mkdtemp(join(tmpdir(), "agent-handshake-proof-"));
  const file = join(directory, "certificate.json");
  await writeFile(file, JSON.stringify(envelope), { mode: 0o600 });
  const { stdout, stderr } = await execFileAsync(process.execPath, [
    "bin/agent-certificate-proof.mjs",
    "--file", file,
    "--role", "initiator",
    "--expected-public-key", fixture.host.publicKey,
    "--session-id", SESSION_ID,
  ], { cwd: new URL("..", import.meta.url) });
  assert.equal(stderr, "");
  assert.deepEqual(JSON.parse(stdout), {
    certificateVerified: true,
    externalActionPerformed: false,
    identity: {
      address: fixture.initiator.address,
      agentId: fixture.initiator.agentId,
      reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${fixture.initiator.agentId}`,
    },
    outcome: "VERIFIED",
    role: "initiator",
    sessionId: SESSION_ID,
    statementDigest: fixture.base.statementDigest,
  });
});
