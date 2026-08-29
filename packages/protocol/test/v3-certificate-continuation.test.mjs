import assert from "node:assert/strict";
import test from "node:test";

import {
  validateHandshakeV3Certificate,
  validateHandshakeV3Continuation,
  verifyHandshakeV3Certificate,
  verifyHandshakeV3Continuation,
} from "@clockchain/handshake-protocol/v3";

const certificate = Object.freeze({
  certificateId: "cert_a",
  schemaVersion: "3.0.0-draft.1",
  sessionId: "sess_a",
  statementDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  policyDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  scopeDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  parties: Object.freeze([
    { role: "INITIATOR", partyDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", signingKeyId: "agent-a-key" },
    { role: "RESPONDER", partyDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", signingKeyId: "agent-b-key" },
  ]),
  issuedAt: "2026-08-29T20:02:00Z",
  expiresAt: "2026-08-29T21:02:00Z",
  clockchainAnchorDigest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  clockchainSignature: Object.freeze({ keyId: "clockchain-root-1", algorithm: "EdDSA", signature: "0123456789abcdef" }),
});

const continuation = Object.freeze({
  continuationId: "cont_a",
  certificateId: "cert_a",
  sessionId: "sess_a",
  statementDigest: certificate.statementDigest,
  policyDigest: certificate.policyDigest,
  scopeDigest: certificate.scopeDigest,
  audience: "agent-contract-a2a",
  actionClass: "A2A_DELIVERY",
  notBefore: "2026-08-29T20:03:00Z",
  expiresAt: "2026-08-29T20:33:00Z",
  replayNonce: "replay_a",
  clockchainSignature: Object.freeze({ keyId: "clockchain-root-1", algorithm: "EdDSA", signature: "abcdef0123456789" }),
});

test("certificate and continuation validators are strict and frozen", () => {
  assert.equal(Object.isFrozen(validateHandshakeV3Certificate(certificate)), true);
  assert.equal(Object.isFrozen(validateHandshakeV3Continuation(continuation)), true);
  assert.throws(() => validateHandshakeV3Certificate({ ...certificate, businessContent: "forbidden" }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3Continuation({ ...continuation, canonicalPayload: { businessContent: "forbidden" } }), { code: "SCHEMA_INVALID" });
});

test("certificate verification checks Clockchain signature and revocation before trusting", async () => {
  let verifierCalls = 0;
  const verified = await verifyHandshakeV3Certificate({
    certificate,
    expectedSessionId: "sess_a",
    expectedStatementDigest: certificate.statementDigest,
    expectedPolicyDigest: certificate.policyDigest,
    expectedScopeDigest: certificate.scopeDigest,
    now: "2026-08-29T20:10:00Z",
    verifyClockchainSignature: async ({ signedDigest, signature }) => {
      verifierCalls += 1;
      assert.match(signedDigest, /^sha256:[0-9a-f]{64}$/);
      assert.deepEqual(signature, certificate.clockchainSignature);
      return true;
    },
    getRevocationStatus: async () => "GOOD",
  });

  assert.equal(verified.verified, true);
  assert.equal(verified.externalBusinessActionPerformed, false);
  assert.equal(verifierCalls, 1);

  await assert.rejects(() => verifyHandshakeV3Certificate({ certificate: { ...certificate, sessionId: "other" }, expectedSessionId: "sess_a", expectedStatementDigest: certificate.statementDigest, expectedPolicyDigest: certificate.policyDigest, expectedScopeDigest: certificate.scopeDigest, now: "2026-08-29T20:10:00Z", verifyClockchainSignature: async () => { throw new Error("must not call"); }, getRevocationStatus: async () => "GOOD" }), { code: "CERTIFICATE_BINDING_MISMATCH" });
  await assert.rejects(() => verifyHandshakeV3Certificate({ certificate, expectedSessionId: "sess_a", expectedStatementDigest: certificate.statementDigest, expectedPolicyDigest: certificate.policyDigest, expectedScopeDigest: certificate.scopeDigest, now: "2026-08-29T20:10:00Z", verifyClockchainSignature: async () => true, getRevocationStatus: async () => "UNKNOWN" }), { code: "REVOCATION_STATUS_UNKNOWN" });
  await assert.rejects(() => verifyHandshakeV3Certificate({ certificate, expectedSessionId: "sess_a", expectedStatementDigest: certificate.statementDigest, expectedPolicyDigest: certificate.policyDigest, expectedScopeDigest: certificate.scopeDigest, now: "2026-08-29T22:10:00Z", verifyClockchainSignature: async () => { throw new Error("must not call"); }, getRevocationStatus: async () => "GOOD" }), { code: "CERTIFICATE_EXPIRED" });
});

test("continuation verification binds certificate, audience, action class, time, replay, and revocation", async () => {
  const seen = new Set();
  const verified = await verifyHandshakeV3Continuation({
    certificate,
    continuation,
    expectedAudience: "agent-contract-a2a",
    expectedActionClass: "A2A_DELIVERY",
    now: "2026-08-29T20:10:00Z",
    verifyClockchainSignature: async () => true,
    getRevocationStatus: async () => "GOOD",
    checkAndRecordReplay: async (nonce) => {
      if (seen.has(nonce)) {
        return false;
      }
      seen.add(nonce);
      return true;
    },
  });
  assert.equal(verified.verified, true);
  assert.equal(verified.safeStop, true);
  assert.equal(verified.externalBusinessActionPerformed, false);

  await assert.rejects(() => verifyHandshakeV3Continuation({ certificate, continuation, expectedAudience: "other", expectedActionClass: "A2A_DELIVERY", now: "2026-08-29T20:10:00Z", verifyClockchainSignature: async () => true, getRevocationStatus: async () => "GOOD", checkAndRecordReplay: async () => true }), { code: "CONTINUATION_BINDING_MISMATCH" });
  await assert.rejects(() => verifyHandshakeV3Continuation({ certificate, continuation, expectedAudience: "agent-contract-a2a", expectedActionClass: "A2A_DELIVERY", now: "2026-08-29T20:10:00Z", verifyClockchainSignature: async () => true, getRevocationStatus: async () => "GOOD", checkAndRecordReplay: async () => false }), { code: "CONTINUATION_REPLAYED" });
  await assert.rejects(() => verifyHandshakeV3Continuation({ certificate, continuation: { ...continuation, notBefore: "2026-08-29T20:30:00Z" }, expectedAudience: "agent-contract-a2a", expectedActionClass: "A2A_DELIVERY", now: "2026-08-29T20:10:00Z", verifyClockchainSignature: async () => true, getRevocationStatus: async () => "GOOD", checkAndRecordReplay: async () => true }), { code: "CONTINUATION_NOT_YET_VALID" });
});
