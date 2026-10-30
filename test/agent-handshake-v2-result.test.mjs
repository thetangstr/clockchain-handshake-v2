import assert from "node:assert/strict";
import { sign } from "node:crypto";
import test from "node:test";

import { canonicalBytes } from "../src/core/canonical.mjs";
import {
  buildAgentHandshakeV2Result,
  verifyAgentHandshakeV2Result,
} from "../src/agent-handshake/v2/result.mjs";
import {
  REPOSITORY_SHA, SESSION_DEADLINE_MS, SESSION_ID, SESSION_OPENED_AT_MS, buildV2Fixture, ed25519,
} from "./support/agent-handshake-v2-fixture.mjs";
import { ed25519PublicKeyFingerprint } from "../src/agent-handshake/v2/host-key-certificate.mjs";

// The fixture's closing certificate is issued at this instant; a verifier
// reads its clock at or after issuance.
const RESULT_ISSUED_AT_MS = 1786337180000;

function trust(fixture) {
  return {
    expectedRepositorySha: REPOSITORY_SHA,
    nowMs: RESULT_ISSUED_AT_MS,
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
    verificationCompletedAtMs: "1786337180000",
  });
  const external = buildAgentHandshakeV2Result({
    hostSessionKeyCertificate: fixture.hostSessionKeyCertificate,
    issuedAtMs: "1786337180000",
    keyId: fixture.host.keyId,
    parties: fixture.parties,
    privateKeyPem: fixture.host.privateKeyPem,
    sessionId: SESSION_ID,
    verdict: { ...fixture.verdict, externalBusinessActionPerformed: true },
    verificationCompletedAtMs: "1786337180000",
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

// The host-signed result with only issuedAtMs changed, re-signed by the
// certified host session key so the signature itself is valid.
function reissued(fixture, issuedAtMs) {
  const result = { ...fixture.resultEnvelope.result, issuedAtMs: String(issuedAtMs) };
  return {
    ...fixture.resultEnvelope,
    result,
    signer: {
      ...fixture.resultEnvelope.signer,
      signature: sign(null, canonicalBytes(result), fixture.host.privateKeyPem).toString("base64"),
    },
  };
}

test("refuses future, pre-certificate and at-or-after-certificate-end issue times; exact nowMs accepted", async () => {
  const fixture = await buildV2Fixture();
  assert.equal(fixture.resultEnvelope.result.issuedAtMs, String(RESULT_ISSUED_AT_MS));
  const validFromMs = Number(SESSION_OPENED_AT_MS);
  const validUntilMs = Number(SESSION_DEADLINE_MS);
  const verifyAt = (envelope, nowMs) => verifyAgentHandshakeV2Result(envelope, {
    ...trust(fixture),
    expectedParty: fixture.parties.initiator,
    expectedPolicyDigest: fixture.parties.initiator.policyDigest,
    expectedRole: "initiator",
    expectedSessionId: SESSION_ID,
    nowMs,
  });
  const nowMs = RESULT_ISSUED_AT_MS;
  const outcome = (issuedAtMs, at) => {
    try { verifyAt(reissued(fixture, issuedAtMs), at); return "accepted"; } catch (error) { return error.name; }
  };
  assert.deepEqual({
    exactNow: outcome(nowMs, nowMs),
    certificateStart: outcome(validFromMs, nowMs),
    futureAtSkew: outcome(nowMs + 120_000, nowMs),
    futurePastSkew: outcome(nowMs + 120_001, nowMs),
    preCertificate: outcome(validFromMs - 1, nowMs),
    certificateLastMs: outcome(validUntilMs - 1, validUntilMs - 1),
    atCertificateEnd: outcome(validUntilMs, validUntilMs - 1),
    afterCertificateEnd: outcome(validUntilMs + 1, validUntilMs - 1),
  }, {
    exactNow: "accepted",
    certificateStart: "accepted",
    futureAtSkew: "accepted",
    futurePastSkew: "AgentHandshakeV2ResultError",
    preCertificate: "AgentHandshakeV2ResultError",
    certificateLastMs: "accepted",
    atCertificateEnd: "AgentHandshakeV2ResultError",
    afterCertificateEnd: "AgentHandshakeV2ResultError",
  });
});

test("the result builder refuses an issue time outside the host-key certificate", async () => {
  const fixture = await buildV2Fixture();
  const build = (issuedAtMs) => {
    try {
      buildAgentHandshakeV2Result({
        hostSessionKeyCertificate: fixture.hostSessionKeyCertificate,
        issuedAtMs: String(issuedAtMs),
        keyId: fixture.host.keyId,
        parties: fixture.parties,
        privateKeyPem: fixture.host.privateKeyPem,
        sessionId: SESSION_ID,
        verdict: fixture.verdict,
        verificationCompletedAtMs: String(issuedAtMs),
      });
      return "built";
    } catch (error) {
      return error.name;
    }
  };
  const validFromMs = Number(SESSION_OPENED_AT_MS);
  const validUntilMs = Number(SESSION_DEADLINE_MS);
  assert.deepEqual({
    preCertificate: build(validFromMs - 1),
    certificateStart: build(validFromMs),
    certificateLastMs: build(validUntilMs - 1),
    atCertificateEnd: build(validUntilMs),
  }, {
    preCertificate: "AgentHandshakeV2ResultError",
    certificateStart: "built",
    certificateLastMs: "built",
    atCertificateEnd: "AgentHandshakeV2ResultError",
  });
});

test("the result builder requires an issue time at or after verification completed", async () => {
  const fixture = await buildV2Fixture();
  const completedAtMs = 1786337175000;
  const build = (options) => {
    try {
      buildAgentHandshakeV2Result({
        hostSessionKeyCertificate: fixture.hostSessionKeyCertificate,
        keyId: fixture.host.keyId,
        parties: fixture.parties,
        privateKeyPem: fixture.host.privateKeyPem,
        sessionId: SESSION_ID,
        verdict: fixture.verdict,
        ...options,
      });
      return "built";
    } catch (error) {
      return error.name;
    }
  };
  assert.deepEqual({
    withoutVerificationTime: build({ issuedAtMs: String(completedAtMs) }),
    malformedVerificationTime: build({ issuedAtMs: String(completedAtMs), verificationCompletedAtMs: "soon" }),
    beforeVerification: build({ issuedAtMs: String(completedAtMs - 1), verificationCompletedAtMs: String(completedAtMs) }),
    atVerification: build({ issuedAtMs: String(completedAtMs), verificationCompletedAtMs: String(completedAtMs) }),
    afterVerification: build({ issuedAtMs: String(completedAtMs + 1), verificationCompletedAtMs: String(completedAtMs) }),
  }, {
    withoutVerificationTime: "AgentHandshakeV2ResultError",
    malformedVerificationTime: "AgentHandshakeV2ResultError",
    beforeVerification: "AgentHandshakeV2ResultError",
    atVerification: "built",
    afterVerification: "built",
  });
});
