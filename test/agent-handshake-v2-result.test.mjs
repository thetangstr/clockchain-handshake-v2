import assert from "node:assert/strict";
import test from "node:test";

import {
  buildAgentHandshakeV2Result,
  verifyAgentHandshakeV2Result,
} from "../src/agent-handshake/v2/result.mjs";
import {
  NOW_MS, REPOSITORY_SHA, SESSION_DEADLINE_MS, SESSION_ID, buildV2Fixture, ed25519,
} from "./support/agent-handshake-v2-fixture.mjs";
import { ed25519PublicKeyFingerprint } from "../src/agent-handshake/v2/host-key-certificate.mjs";

function trust(fixture) {
  return {
    expectedRepositorySha: REPOSITORY_SHA,
    nowMs: NOW_MS,
    rootKeyRing: [{
      kid: fixture.root.keyId,
      publicKey: fixture.hostSessionKeyCertificate.rootSignature.publicKey,
      fingerprint: ed25519PublicKeyFingerprint(fixture.hostSessionKeyCertificate.rootSignature.publicKey),
    }],
    sessionDeadlineMs: Number(SESSION_DEADLINE_MS),
  };
}

test("both roles verify the same root-pinned closing certificate and policy digest", async () => {
  const fixture = await buildV2Fixture();
  for (const role of ["initiator", "responder"]) {
    const proof = verifyAgentHandshakeV2Result(fixture.resultEnvelope, {
      ...trust(fixture),
      expectedParty: fixture.parties[role],
      expectedPolicyDigest: fixture.parties[role].policyDigest,
      expectedRole: role,
      expectedSessionId: SESSION_ID,
    });
    assert.equal(proof.certificateVerified, true);
    assert.equal(proof.externalBusinessActionPerformed, false);
  }
});

test("foreign host, session, role, party, policy, negative outcome, and external action fail", async () => {
  const fixture = await buildV2Fixture();
  const foreign = ed25519("foreign-session");
  const negative = buildAgentHandshakeV2Result({
    hostSessionKeyCertificate: fixture.hostSessionKeyCertificate,
    issuedAtMs: "1786337180000",
    keyId: fixture.host.keyId,
    parties: fixture.parties,
    privateKeyPem: fixture.host.privateKeyPem,
    sessionId: SESSION_ID,
    verdict: { ...fixture.verdict, outcome: "FAILED" },
  });
  const external = buildAgentHandshakeV2Result({
    hostSessionKeyCertificate: fixture.hostSessionKeyCertificate,
    issuedAtMs: "1786337180000",
    keyId: fixture.host.keyId,
    parties: fixture.parties,
    privateKeyPem: fixture.host.privateKeyPem,
    sessionId: SESSION_ID,
    verdict: { ...fixture.verdict, externalBusinessActionPerformed: true },
  });
  for (const [envelope, options] of [
    [fixture.resultEnvelope, { expectedSessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }],
    [fixture.resultEnvelope, { expectedRole: "responder", expectedParty: fixture.parties.initiator }],
    [fixture.resultEnvelope, { expectedPolicyDigest: "f".repeat(64) }],
    [negative, {}],
    [external, {}],
  ]) {
    assert.throws(() => verifyAgentHandshakeV2Result(envelope, {
      ...trust(fixture),
      expectedParty: fixture.parties.initiator,
      expectedPolicyDigest: fixture.parties.initiator.policyDigest,
      expectedRole: "initiator",
      expectedSessionId: SESSION_ID,
      ...options,
    }));
  }
  assert.notEqual(foreign.publicKey, fixture.host.publicKey);
});
