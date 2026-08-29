import assert from "node:assert/strict";
import test from "node:test";

import {
  createHandshakeV3SigningRequest,
  recoverHandshakeV3RoleGrant,
  validateHandshakeV3RoleGrant,
  validateHandshakeV3SignedAction,
  verifyHandshakeV3SignedAction,
} from "@clockchain/handshake-protocol/v3";

const baseGrant = Object.freeze({
  roleGrantId: "grant_a",
  sessionId: "sess_a",
  role: "INITIATOR",
  principalDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  proofKeyThumbprint: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  allowedTools: ["agent_handshake_session_next", "agent_handshake_session_submit"],
  issuedAt: "2026-08-29T20:00:00Z",
  expiresAt: "2026-08-29T21:00:00Z",
});

test("role grants are bound to session, role, principal, proof key, allowed tool, and expiry", () => {
  const grant = validateHandshakeV3RoleGrant(baseGrant, {
    sessionId: "sess_a",
    role: "INITIATOR",
    principalDigest: baseGrant.principalDigest,
    proofKeyThumbprint: baseGrant.proofKeyThumbprint,
    tool: "agent_handshake_session_next",
    now: "2026-08-29T20:30:00Z",
  });

  assert.equal(Object.isFrozen(grant), true);
  assert.throws(() => validateHandshakeV3RoleGrant(baseGrant, { ...baseGrant, tool: "agent_handshake_session_verify", now: "2026-08-29T20:30:00Z" }), { code: "ROLE_GRANT_TOOL_DENIED" });
  assert.throws(() => validateHandshakeV3RoleGrant(baseGrant, { ...baseGrant, sessionId: "sess_b", tool: "agent_handshake_session_next", now: "2026-08-29T20:30:00Z" }), { code: "ROLE_GRANT_BOUNDARY_MISMATCH" });
  assert.throws(() => validateHandshakeV3RoleGrant(baseGrant, { ...baseGrant, tool: "agent_handshake_session_next", now: "2026-08-29T22:00:00Z" }), { code: "ROLE_GRANT_EXPIRED" });
});

test("same-identity recovery returns a new grant without mutating protocol state", () => {
  const recovered = recoverHandshakeV3RoleGrant(baseGrant, {
    roleGrantId: "grant_recovered",
    principalDigest: baseGrant.principalDigest,
    proofKeyThumbprint: baseGrant.proofKeyThumbprint,
    now: "2026-08-29T20:31:00Z",
  });

  assert.equal(recovered.roleGrantId, "grant_recovered");
  assert.equal(recovered.recoveredWithoutMutation, true);
  assert.equal(recovered.protocolStateMutated, false);
  assert.equal(recovered.sessionId, baseGrant.sessionId);
  assert.equal(recovered.role, baseGrant.role);
  assert.throws(() => recoverHandshakeV3RoleGrant(baseGrant, { roleGrantId: "grant_bad", principalDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", proofKeyThumbprint: baseGrant.proofKeyThumbprint, now: "2026-08-29T20:31:00Z" }), { code: "ROLE_GRANT_RECOVERY_DENIED" });
});

test("typed signing requests bind canonical bytes and signed actions never carry free-form payloads", async () => {
  const request = createHandshakeV3SigningRequest({
    signingRequestId: "signreq_a",
    actionType: "PROPOSAL",
    sessionId: "sess_a",
    stateVersion: 4,
    role: "INITIATOR",
    policyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    statementDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    counterpartyDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    priorEventDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    evidenceDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    nonce: "nonce_a",
    issuedAt: "2026-08-29T20:00:00Z",
    expiresAt: "2026-08-29T20:05:00Z",
  });
  const action = validateHandshakeV3SignedAction({
    signingRequestId: request.signingRequestId,
    signingDigest: request.signingDigest,
    signerKeyId: "agent-a-key-1",
    algorithm: "EdDSA",
    signature: "0123456789abcdef",
  });

  assert.match(request.canonicalBytesBase64Url, /^[A-Za-z0-9_-]+$/);
  assert.equal(request.domainSeparator, "CLOCKCHAIN_AGENT_HANDSHAKE_V3");
  assert.equal(request.canonicalization, "RFC8785");
  assert.equal(action.signingDigest, request.signingDigest);
  assert.throws(() => validateHandshakeV3SignedAction({ ...action, canonicalPayload: { businessContent: "forbidden" } }), { code: "SCHEMA_INVALID" });

  let verifierCalls = 0;
  const verified = await verifyHandshakeV3SignedAction({
    request,
    action,
    expectedRole: "INITIATOR",
    expectedSignerKeyId: "agent-a-key-1",
    now: "2026-08-29T20:01:00Z",
    verifier: async ({ bytes, signature, keyId, algorithm }) => {
      verifierCalls += 1;
      assert.equal(Buffer.from(bytes).toString("base64url"), request.canonicalBytesBase64Url);
      assert.equal(signature, action.signature);
      assert.equal(keyId, action.signerKeyId);
      assert.equal(algorithm, "EdDSA");
      return true;
    },
  });
  assert.equal(verified.verified, true);
  assert.equal(verifierCalls, 1);

  await assert.rejects(
    () => verifyHandshakeV3SignedAction({ request, action: { ...action, signingDigest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" }, expectedRole: "INITIATOR", expectedSignerKeyId: "agent-a-key-1", now: "2026-08-29T20:01:00Z", verifier: async () => { throw new Error("must not call"); } }),
    { code: "SIGNING_REQUEST_MISMATCH" },
  );
  await assert.rejects(
    () => verifyHandshakeV3SignedAction({ request, action, expectedRole: "RESPONDER", expectedSignerKeyId: "agent-a-key-1", now: "2026-08-29T20:01:00Z", verifier: async () => { throw new Error("must not call"); } }),
    { code: "SIGNING_REQUEST_ROLE_MISMATCH" },
  );
});
