import assert from "node:assert/strict";
import test from "node:test";

import {
  HANDSHAKE_V3_DOMAIN_SEPARATOR,
  applyHandshakeV3Transition,
  createHandshakeV3SigningRequest,
  evaluateHandshakeV3OperatorRequest,
  handshakeV3CertificateSignedProjection,
  handshakeV3ContinuationSignedProjection,
  handshakeV3Digest,
  recoverHandshakeV3RoleGrant,
  validateHandshakeV3RoleGrantBinding,
  validateHandshakeV3ToolResult,
  verifyHandshakeV3Continuation,
  verifyHandshakeV3SignedAction,
} from "@clockchain/handshake-protocol/v3";

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const digestC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const digestD = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const digestE = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const digestF = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

function policy() {
  return {
    scope: ["agent-contract:a2a"],
    constraints: { mode: "verify-only" },
    externalBusinessActionsAllowed: false,
    expiresAt: "2026-08-29T21:00:00Z",
  };
}

function session(state = "INVITED", stateVersion = 0) {
  return {
    sessionId: "sess_0123456789abcdef",
    role: "INITIATOR",
    state,
    stateVersion,
    policy: policy(),
    policyDigest: digestA,
    expiresAt: "2026-08-29T21:00:00Z",
    allowedTransitions: [],
    eventCursor: "cursor_0123456789abcdef",
  };
}

function roleGrant() {
  return {
    roleGrantId: "grant_0123456789abcdef",
    sessionId: "sess_0123456789abcdef",
    role: "INITIATOR",
    principalDigest: digestB,
    proofKeyThumbprint: digestC,
    allowedTools: ["agent_handshake_session_next", "agent_handshake_session_submit"],
    expiresAt: "2026-08-29T21:00:00Z",
  };
}

function certificate() {
  const unsigned = {
    certificateId: "cert_0123456789abcdef",
    sessionId: "sess_0123456789abcdef",
    certificateDigest: digestA,
    policyDigest: digestA,
    partyDigests: [digestB, digestC],
    clockchainNetwork: "sepolia",
    trustRootId: "root-2026-08",
    issuedAt: "2026-08-29T20:00:00Z",
    expiresAt: "2026-08-29T21:00:00Z",
    issuerSignature: "s".repeat(32),
  };
  const certificateDigest = handshakeV3Digest(handshakeV3CertificateSignedProjection(unsigned));
  return { ...unsigned, certificateDigest };
}

function continuation(cert = certificate()) {
  return {
    continuationId: "cont_0123456789abcdef",
    sessionId: cert.sessionId,
    federationRelationDigest: digestD,
    certificateDigest: cert.certificateDigest,
    clockchainNetwork: cert.clockchainNetwork,
    trustRootId: cert.trustRootId,
    partyRoleDigests: [digestE, digestF],
    statementDigest: digestB,
    scopeDigest: digestC,
    policyDigest: cert.policyDigest,
    protocolVersion: "3.0",
    schemaVersion: "3.0.0-draft.1",
    issuedAt: "2026-08-29T20:01:00Z",
    notBefore: "2026-08-29T20:02:00Z",
    expiresAt: "2026-08-29T20:30:00Z",
    audience: "agent-contract-a2a",
    allowedNextActionClass: "A2A_DELIVERY",
    replayNonce: "replay_0123456789abcdef",
    revocationHandle: "revoke_0123456789abcdef",
    issuerSignature: "c".repeat(32),
  };
}

test("role grants bind principal, proof key, tool, and expiry with schema error codes", () => {
  assert.equal(validateHandshakeV3RoleGrantBinding(roleGrant(), {
    sessionId: "sess_0123456789abcdef",
    role: "INITIATOR",
    principalDigest: digestB,
    proofKeyThumbprint: digestC,
    tool: "agent_handshake_session_next",
    now: "2026-08-29T20:30:00Z",
  }).roleGrantId, "grant_0123456789abcdef");
  assert.throws(() => validateHandshakeV3RoleGrantBinding(roleGrant(), { principalDigest: digestC }), { code: "PRINCIPAL_DENIED" });
  assert.throws(() => validateHandshakeV3RoleGrantBinding(roleGrant(), { proofKeyThumbprint: digestB }), { code: "SENDER_CONSTRAINT_INVALID" });
  assert.throws(() => validateHandshakeV3RoleGrantBinding(roleGrant(), { tool: "agent_handshake_operator_request" }), { code: "SCOPE_DENIED" });
});

test("recovery returns exact roleGrant/session/result shape and does not mutate session", () => {
  const original = session("PROPOSAL_PENDING", 5);
  const recovered = recoverHandshakeV3RoleGrant(roleGrant(), {
    roleGrantId: "grant_recovered_123",
    principalDigest: digestB,
    proofKeyThumbprint: digestC,
    now: "2026-08-29T20:30:00Z",
    session: original,
  });
  assert.deepEqual(recovered.session, original);
  assert.equal(recovered.recoveredWithoutMutation, true);
  assert.equal(recovered.roleGrant.roleGrantId, "grant_recovered_123");
  assert.deepEqual(validateHandshakeV3ToolResult("agent_handshake_session_resume", recovered), recovered);
});

test("typed signing request bytes use exact schema fields and signer negatives do not call verifier", async () => {
  const request = createHandshakeV3SigningRequest({
    signingRequestId: "signreq_0123456789abcdef",
    actionType: "PROPOSAL",
    sessionId: "sess_0123456789abcdef",
    stateVersion: 4,
    role: "INITIATOR",
    policyDigest: digestA,
    statementDigest: digestB,
    counterpartIdentityDigest: digestC,
    priorActionDigest: digestD,
    evidenceDigest: digestE,
    nonce: "nonce_0123456789abcdef",
    issuedAt: "2026-08-29T20:00:00Z",
    expiresAt: "2026-08-29T20:05:00Z",
  });
  const bytes = JSON.parse(Buffer.from(request.canonicalBytesBase64Url, "base64url").toString("utf8"));
  assert.equal(bytes.domainSeparator, HANDSHAKE_V3_DOMAIN_SEPARATOR);
  assert.equal(bytes.counterpartIdentityDigest, digestC);
  assert.equal(bytes.priorActionDigest, digestD);
  assert.equal(bytes.counterpartyDigest, undefined);

  let calls = 0;
  const action = {
    signingRequestId: request.signingRequestId,
    signingDigest: request.signingDigest,
    signerKeyId: "agent-a-key",
    algorithm: "EdDSA",
    signature: "0".repeat(32),
  };
  await verifyHandshakeV3SignedAction({
    request,
    action,
    expectedRole: "INITIATOR",
    expectedSignerKeyId: "agent-a-key",
    now: "2026-08-29T20:01:00Z",
    verifier: async () => {
      calls += 1;
      return true;
    },
  });
  assert.equal(calls, 1);
  await assert.rejects(() => verifyHandshakeV3SignedAction({
    request,
    action: { ...action, signingDigest: digestF },
    expectedRole: "INITIATOR",
    expectedSignerKeyId: "agent-a-key",
    now: "2026-08-29T20:01:00Z",
    verifier: async () => {
      throw new Error("must not call");
    },
  }), { code: "SIGNATURE_INVALID" });
});

test("lifecycle emits exact public sessions and schema error codes", () => {
  let current = session();
  for (const [actionType, nextState, actor] of [
    ["CLAIM_INVITATION", "CLAIMED", "RESPONDER"],
    ["PREPARE_POLICY", "POLICY_READY", "INITIATOR"],
    ["BIND_PARTIES", "PARTIES_BOUND", "INITIATOR"],
    ["SUBMIT_PROPOSAL", "PROPOSAL_PENDING", "INITIATOR"],
    ["SUBMIT_ACCEPTANCE", "ACCEPTANCE_PENDING", "RESPONDER"],
    ["CONFIRM_ANCHOR", "ANCHORING", "CLOCKCHAIN"],
    ["ISSUE_CERTIFICATE", "CERTIFICATE_ISSUED", "CLOCKCHAIN"],
    ["ISSUE_CONTINUATION", "CONTINUATION_ISSUED", "CLOCKCHAIN"],
    ["COMPLETE", "COMPLETED", "CLOCKCHAIN"],
  ]) {
    const result = applyHandshakeV3Transition(current, { actionType, actor, expectedStateVersion: current.stateVersion });
    assert.equal(result.allowed, true);
    assert.equal(result.session.state, nextState);
    current = result.session;
  }
  assert.equal(applyHandshakeV3Transition(current, { actionType: "COMPLETE", actor: "CLOCKCHAIN", expectedStateVersion: current.stateVersion }).error.code, "TRANSITION_DENIED");
  assert.equal(applyHandshakeV3Transition(session("PARTIES_BOUND", 3), { actionType: "SUBMIT_PROPOSAL", actor: "OPERATOR", expectedStateVersion: 3 }).error.code, "ROLE_DENIED");
  assert.equal(applyHandshakeV3Transition(session("PARTIES_BOUND", 3), { actionType: "SUBMIT_PROPOSAL", actor: "INITIATOR", expectedStateVersion: 2 }).error.code, "STATE_VERSION_CONFLICT");
  assert.equal(applyHandshakeV3Transition(session("PROPOSAL_PENDING", 4), { actionType: "CANCEL", actor: "RESPONDER", expectedStateVersion: 4 }).session.state, "CANCELLED");
  assert.equal(applyHandshakeV3Transition(session("PROPOSAL_PENDING", 4), { actionType: "EXPIRE", actor: "SYSTEM", expectedStateVersion: 4 }).session.state, "EXPIRED");
});

test("operator request remains request-only and never mutates protocol state", () => {
  const original = session("PROPOSAL_PENDING", 5);
  const result = evaluateHandshakeV3OperatorRequest(original, {
    action: "REQUEST_EXPIRY_EVALUATION",
    observedStateVersion: 5,
  });
  assert.deepEqual(validateHandshakeV3ToolResult("agent_handshake_operator_request", result), result);
  assert.equal(result.requestOnly, true);
  assert.deepEqual(result.session, original);
  assert.throws(() => evaluateHandshakeV3OperatorRequest(original, { action: "RECOVER_AGENT_ROLE", observedStateVersion: 5 }), { code: "SCHEMA_INVALID" });
});

test("continuation verification validates signatures before bindings, revocation, and replay", async () => {
  const cert = certificate();
  const cont = continuation(cert);
  assert.match(handshakeV3Digest(handshakeV3CertificateSignedProjection(cert)), /^sha256:[0-9a-f]{64}$/);
  assert.match(handshakeV3Digest(handshakeV3ContinuationSignedProjection(cont)), /^sha256:[0-9a-f]{64}$/);

  const calls = [];
  const result = await verifyHandshakeV3Continuation({
    certificate: cert,
    continuation: cont,
    expectedCertificateDigest: cert.certificateDigest,
    expectedPartyRoleDigests: cont.partyRoleDigests,
    expectedStatementDigest: cont.statementDigest,
    expectedScopeDigest: cont.scopeDigest,
    expectedPolicyDigest: cont.policyDigest,
    expectedAudience: "agent-contract-a2a",
    expectedAllowedNextActionClass: "A2A_DELIVERY",
    now: "2026-08-29T20:10:00Z",
    verifyIssuerSignature: async ({ signedDigest }) => {
      calls.push(["signature", signedDigest]);
      return true;
    },
    getRevocationStatus: async () => {
      calls.push(["revocation"]);
      return "GOOD";
    },
    checkAndRecordReplay: async () => {
      calls.push(["replay"]);
      return true;
    },
  });
  assert.equal(result.valid, true);
  assert.equal(result.externalBusinessActionPerformed, false);
  assert.deepEqual(calls.map(([name]) => name), ["signature", "signature", "revocation", "replay"]);

  const noReplayCalls = [];
  await assert.rejects(() => verifyHandshakeV3Continuation({
    certificate: cert,
    continuation: cont,
    now: "2026-08-29T20:10:00Z",
    verifyIssuerSignature: async () => false,
    getRevocationStatus: async () => {
      noReplayCalls.push("revocation");
      return "GOOD";
    },
    checkAndRecordReplay: async () => {
      noReplayCalls.push("replay");
      return true;
    },
  }), { code: "SIGNATURE_INVALID" });
  assert.deepEqual(noReplayCalls, []);
});
