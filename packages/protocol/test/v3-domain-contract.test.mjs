import assert from "node:assert/strict";
import test from "node:test";

import {
  HANDSHAKE_V3_ALLOWED_TRANSITIONS_BY_STATE,
  HANDSHAKE_V3_DOMAIN_SEPARATOR,
  HANDSHAKE_V3_INITIATOR_REQUIRED_TOOLS,
  applyHandshakeV3Transition,
  applyHandshakeV3ToolEvent,
  createHandshakeV3Aggregate,
  createHandshakeV3PolicyDigest,
  createHandshakeV3StatementDigest,
  createHandshakeV3SigningRequest,
  evaluateHandshakeV3OperatorRequest,
  handshakeV3CertificateSignedProjection,
  handshakeV3ContinuationSignedProjection,
  handshakeV3Digest,
  recoverHandshakeV3RoleGrant,
  createHandshakeV3RoleGrantRecoveryAuditEvent,
  planHandshakeV3NextAction,
  projectHandshakeV3SessionForRole,
  validateHandshakeV3ActionSubmission,
  validateHandshakeV3CheckpointSubmission,
  validateHandshakeV3RoleGrantBinding,
  validateHandshakeV3ToolInput,
  validateHandshakeV3ToolResult,
  verifyHandshakeV3Certificate,
  verifyHandshakeV3Continuation,
  verifyHandshakeV3SignedAction,
} from "@clockchain/handshake-protocol/v3";

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const digestC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const digestD = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const digestE = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const digestF = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

async function assertRejectsWithoutLeak(fn, code) {
  try {
    await fn();
    assert.fail(`Expected ${code}`);
  } catch (error) {
    assert.equal(error.code, code);
    assert.doesNotMatch(error.message, /secret|raw|callback|boom/i);
  }
}

function policy() {
  return {
    scope: ["agent-contract:a2a"],
    constraints: { mode: "verify-only" },
    externalBusinessActionsAllowed: false,
    expiresAt: "2026-08-29T21:00:00Z",
  };
}

function agentParty(role) {
  return {
    role,
    identityDigest: role === "INITIATOR" ? digestB : digestC,
    publicKey: `${role.toLowerCase()}-public-key-0123456789abcdef0123456789abcdef`,
    signingKeyId: role === "INITIATOR" ? "agent-a-key-1" : "agent-b-key-1",
    signingAlgorithm: "EdDSA",
  };
}

function toolInputForAction(aggregate, plan, role, signature = role === "INITIATOR" ? "p".repeat(32) : "a".repeat(32)) {
  return {
    sessionId: aggregate.sessionId,
    roleGrantId: `grant.${role.toLowerCase()}.000`,
    action: {
      signingRequestId: plan.session.pendingSigningRequest.signingRequestId,
      signingDigest: plan.session.pendingSigningRequest.signingDigest,
      signerKeyId: agentParty(role).signingKeyId,
      algorithm: agentParty(role).signingAlgorithm,
      signature,
    },
    idempotencyKey: `idem.${role.toLowerCase()}.${aggregate.stateVersion}`,
    expectedStateVersion: aggregate.stateVersion,
  };
}

function toolInputForCheckpoint(aggregate, plan, signature = "e".repeat(32)) {
  return {
    sessionId: aggregate.sessionId,
    roleGrantId: "grant.responder.000",
    checkpointType: "ACCEPTED",
    signingRequestId: plan.session.pendingSigningRequest.signingRequestId,
    signingDigest: plan.session.pendingSigningRequest.signingDigest,
    signerKeyId: agentParty("RESPONDER").signingKeyId,
    algorithm: agentParty("RESPONDER").signingAlgorithm,
    signature,
    idempotencyKey: `idem.responder.checkpoint.${aggregate.stateVersion}`,
    expectedStateVersion: aggregate.stateVersion,
  };
}

const acceptingVerifier = async () => true;
const rejectingVerifier = async () => false;

function throwingGetterRecord(key = "type") {
  return Object.defineProperty({}, key, {
    enumerable: true,
    get() {
      throw new Error("secret raw getter boom");
    },
  });
}

function throwingOwnKeysProxy() {
  return new Proxy({}, {
    ownKeys() {
      throw new Error("secret raw proxy boom");
    },
  });
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
    allowedTransitions: [...HANDSHAKE_V3_ALLOWED_TRANSITIONS_BY_STATE[state]],
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
    allowedTools: [...HANDSHAKE_V3_INITIATOR_REQUIRED_TOOLS],
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

function signedCertificate(overrides) {
  const candidate = { ...certificate(), ...overrides };
  return {
    ...candidate,
    certificateDigest: handshakeV3Digest(handshakeV3CertificateSignedProjection(candidate)),
  };
}

function continuation(cert = certificate()) {
  return {
    continuationId: "cont_0123456789abcdef",
    sessionId: cert.sessionId,
    federationRelationDigest: digestD,
    certificateDigest: cert.certificateDigest,
    clockchainNetwork: cert.clockchainNetwork,
    trustRootId: cert.trustRootId,
    partyRoleDigests: cert.partyDigests,
    statementDigest: digestB,
    scopeDigest: digestC,
    policyDigest: cert.policyDigest,
    protocolVersion: "3.0",
    schemaVersion: "3.0.0-draft.3",
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
  assert.throws(() => validateHandshakeV3RoleGrantBinding({
    ...roleGrant(),
    expiresAt: "2026-08-29T20:00:60Z",
  }, { now: "2026-08-29T20:01:00Z" }), { code: "TOKEN_EXPIRED" });
});

test("draft.3 stateful two-agent vector reaches verified safe stop without business action", async () => {
  const sessionId = "sess_stateful_012345";
  const base = createHandshakeV3Aggregate({
    sessionId,
    policy: policy(),
    expiresAt: "2026-08-29T21:00:00Z",
    statement: "Agent Contract handshake only; stop before business action.",
    createdAt: "2026-08-29T20:00:00Z",
  });
  assert.equal(base.schemaVersion, "3.0.0-draft.3");
  assert.equal(base.policyDigest, createHandshakeV3PolicyDigest(policy()));
  assert.equal(base.statementDigest, createHandshakeV3StatementDigest("Agent Contract handshake only; stop before business action."));

  const accepted = applyHandshakeV3ToolEvent(base, {
    type: "INVITATION_ACCEPTED",
    expectedStateVersion: base.stateVersion,
    role: "RESPONDER",
    partyDigest: digestC,
    eventCursor: "cursor_accept_012345",
  });
  assert.equal(planHandshakeV3NextAction(accepted, "INITIATOR").nextAction, "JOIN_SESSION");
  assert.equal(planHandshakeV3NextAction(accepted, "RESPONDER").nextAction, "JOIN_SESSION");

  const initiatorJoined = applyHandshakeV3ToolEvent(accepted, {
    type: "SESSION_JOINED",
    expectedStateVersion: accepted.stateVersion,
    role: "INITIATOR",
    partyDigest: digestB,
    eventCursor: "cursor_join_i_012345",
  });
  const responderJoinPlan = planHandshakeV3NextAction(initiatorJoined, "RESPONDER");
  assert.equal(responderJoinPlan.nextAction, "JOIN_SESSION");
  assert.equal(responderJoinPlan.requiredTool, "agent_handshake_session_join");

  const callbackEvents = [{
    eventId: "01234567-89ab-4def-8123-456789abcdef",
    sessionId,
    state: initiatorJoined.state,
    stateVersion: initiatorJoined.stateVersion,
    eventCursor: initiatorJoined.eventCursor,
    eventDigest: digestD,
    occurredAt: "2026-08-29T20:00:01Z",
    signature: "fixture-callback-signature-0123456789abcdef",
  }];
  const changedWait = planHandshakeV3NextAction(initiatorJoined, "INITIATOR", {
    changed: true,
    events: callbackEvents,
  });
  assert.equal(changedWait.nextAction, "WAIT");
  assert.equal(changedWait.changed, true);
  assert.deepEqual(changedWait.events, callbackEvents);

  const bothJoined = applyHandshakeV3ToolEvent(initiatorJoined, {
    type: "SESSION_JOINED",
    expectedStateVersion: initiatorJoined.stateVersion,
    role: "RESPONDER",
    partyDigest: digestC,
    eventCursor: "cursor_join_r_012345",
  });
  const initiatorPlan = planHandshakeV3NextAction(bothJoined, "INITIATOR");
  const responderWait = planHandshakeV3NextAction(bothJoined, "RESPONDER");
  assert.equal(projectHandshakeV3SessionForRole(bothJoined, "INITIATOR").state, "PARTIES_BOUND");
  assert.equal(initiatorPlan.nextAction, "SIGN_AND_SUBMIT");
  assert.equal(initiatorPlan.session.pendingSigningRequest.actionType, "PROPOSAL");
  assert.equal(responderWait.nextAction, "WAIT");

  const proposalEvent = await validateHandshakeV3ActionSubmission(bothJoined, {
    toolInput: toolInputForAction(bothJoined, initiatorPlan, "INITIATOR"),
    expectedParty: agentParty("INITIATOR"),
    verifier: acceptingVerifier,
    now: "2026-08-29T20:00:01Z",
    eventCursor: "cursor_proposal_012345",
  });
  const proposalSubmitted = applyHandshakeV3ToolEvent(bothJoined, proposalEvent);
  const responderPlan = planHandshakeV3NextAction(proposalSubmitted, "RESPONDER");
  assert.equal(responderPlan.nextAction, "SIGN_AND_SUBMIT");
  assert.equal(responderPlan.session.pendingSigningRequest.actionType, "ACCEPTANCE");
  assert.equal(planHandshakeV3NextAction(proposalSubmitted, "INITIATOR").nextAction, "WAIT");

  const acceptanceSubmitted = applyHandshakeV3ToolEvent(proposalSubmitted, await validateHandshakeV3ActionSubmission(proposalSubmitted, {
    toolInput: toolInputForAction(proposalSubmitted, responderPlan, "RESPONDER"),
    expectedParty: agentParty("RESPONDER"),
    verifier: acceptingVerifier,
    now: "2026-08-29T20:00:02Z",
    eventCursor: "cursor_acceptance_012345",
  }));
  const checkpointPlan = planHandshakeV3NextAction(acceptanceSubmitted, "RESPONDER");
  assert.equal(checkpointPlan.nextAction, "SUBMIT_CHECKPOINT");
  assert.equal(checkpointPlan.session.pendingSigningRequest.actionType, "EVIDENCE");

  const anchoring = applyHandshakeV3ToolEvent(acceptanceSubmitted, await validateHandshakeV3CheckpointSubmission(acceptanceSubmitted, {
    toolInput: toolInputForCheckpoint(acceptanceSubmitted, checkpointPlan),
    expectedParty: agentParty("RESPONDER"),
    verifier: acceptingVerifier,
    now: "2026-08-29T20:00:03Z",
    eventCursor: "cursor_checkpoint_012345",
  }));
  assert.equal(anchoring.state, "ANCHORING");

  const certificateIssued = applyHandshakeV3ToolEvent(anchoring, {
    type: "CLOCKCHAIN_CERTIFICATE_ISSUED",
    expectedStateVersion: anchoring.stateVersion,
    certificateDigest: digestD,
    eventCursor: "cursor_cert_012345",
  });
  assert.equal(planHandshakeV3NextAction(certificateIssued, "INITIATOR").nextAction, "WAIT");

  const continuationIssued = applyHandshakeV3ToolEvent(certificateIssued, {
    type: "CLOCKCHAIN_CONTINUATION_ISSUED",
    expectedStateVersion: certificateIssued.stateVersion,
    certificateDigest: digestD,
    continuationDigest: digestE,
    eventCursor: "cursor_cont_012345",
  });
  assert.equal(planHandshakeV3NextAction(continuationIssued, "RESPONDER").nextAction, "FETCH_RESULT");
  assert.equal(continuationIssued.externalBusinessActionPerformed, false);
});

test("draft.3 reducer rejects stale, out-of-order, and mutated lifecycle events", async () => {
  const base = createHandshakeV3Aggregate({
    sessionId: "sess_guarded_012345",
    policy: policy(),
    expiresAt: "2026-08-29T21:00:00Z",
    statement: "guarded reducer",
  });
  assert.throws(() => applyHandshakeV3ToolEvent(base, {
    type: "CLOCKCHAIN_CONTINUATION_ISSUED",
    expectedStateVersion: base.stateVersion,
    certificateDigest: digestD,
    continuationDigest: digestE,
  }), { code: "TRANSITION_DENIED" });
  assert.throws(() => applyHandshakeV3ToolEvent(base, {
    type: "ACTION_SUBMITTED",
    expectedStateVersion: base.stateVersion,
    role: "INITIATOR",
    actionType: "PROPOSAL",
    signingDigest: digestD,
  }), { code: "TRANSITION_DENIED" });
  assert.throws(() => applyHandshakeV3ToolEvent(base, {
    type: "INVITATION_ACCEPTED",
    expectedStateVersion: 99,
    role: "RESPONDER",
    partyDigest: digestC,
  }), { code: "STATE_VERSION_CONFLICT" });

  const accepted = applyHandshakeV3ToolEvent(base, {
    type: "INVITATION_ACCEPTED",
    expectedStateVersion: base.stateVersion,
    role: "RESPONDER",
    partyDigest: digestC,
  });
  const initiatorJoined = applyHandshakeV3ToolEvent(accepted, {
    type: "SESSION_JOINED",
    expectedStateVersion: accepted.stateVersion,
    role: "INITIATOR",
    partyDigest: digestB,
    eventCursor: "cursor.join.i.000",
  });
  const replayed = applyHandshakeV3ToolEvent(initiatorJoined, {
    type: "SESSION_JOINED",
    expectedStateVersion: initiatorJoined.stateVersion,
    role: "INITIATOR",
    partyDigest: digestB,
    eventCursor: "cursor.join.i.000",
  });
  assert.equal(replayed.stateVersion, initiatorJoined.stateVersion);
  assert.equal(replayed.eventChainDigest, initiatorJoined.eventChainDigest);
  assert.deepEqual(replayed.joinedPartyDigests, initiatorJoined.joinedPartyDigests);

  assert.throws(() => applyHandshakeV3ToolEvent(initiatorJoined, {
    type: "SESSION_JOINED",
    expectedStateVersion: initiatorJoined.stateVersion,
    role: "INITIATOR",
    partyDigest: digestD,
  }), { code: "IDEMPOTENCY_CONFLICT" });
  const bothJoined = applyHandshakeV3ToolEvent(initiatorJoined, {
    type: "SESSION_JOINED",
    expectedStateVersion: initiatorJoined.stateVersion,
    role: "RESPONDER",
    partyDigest: digestC,
  });
  assert.equal(bothJoined.state, "PARTIES_BOUND");
  assert.throws(() => applyHandshakeV3ToolEvent(bothJoined, {
    type: "SESSION_JOINED",
    expectedStateVersion: bothJoined.stateVersion,
    role: "RESPONDER",
    partyDigest: digestC,
  }), { code: "TRANSITION_DENIED" });
  assert.throws(() => applyHandshakeV3ToolEvent(bothJoined, {
    type: "CLOCKCHAIN_CERTIFICATE_ISSUED",
    expectedStateVersion: bothJoined.stateVersion,
    certificateDigest: digestD,
  }), { code: "TRANSITION_DENIED" });

  const plan = planHandshakeV3NextAction(bothJoined, "INITIATOR");
  await assert.rejects(() => validateHandshakeV3ActionSubmission(base, {
    toolInput: toolInputForAction(base, {
      session: { pendingSigningRequest: plan.session.pendingSigningRequest },
    }, "INITIATOR"),
    expectedParty: agentParty("INITIATOR"),
    verifier: acceptingVerifier,
    now: "2026-08-29T20:00:01Z",
  }), { code: "TRANSITION_DENIED" });
});

test("draft.3 submissions require exact tool input, fresh state, matching pending request, and verified signatures", async () => {
  const base = createHandshakeV3Aggregate({
    sessionId: "sess_submit_guard_012345",
    policy: policy(),
    expiresAt: "2026-08-29T21:00:00Z",
    statement: "guarded submit",
    createdAt: "2026-08-29T20:00:00Z",
  });
  const accepted = applyHandshakeV3ToolEvent(base, {
    type: "INVITATION_ACCEPTED",
    expectedStateVersion: base.stateVersion,
    role: "RESPONDER",
    partyDigest: digestC,
  });
  const initiatorJoined = applyHandshakeV3ToolEvent(accepted, {
    type: "SESSION_JOINED",
    expectedStateVersion: accepted.stateVersion,
    role: "INITIATOR",
    partyDigest: digestB,
  });
  const bothJoined = applyHandshakeV3ToolEvent(initiatorJoined, {
    type: "SESSION_JOINED",
    expectedStateVersion: initiatorJoined.stateVersion,
    role: "RESPONDER",
    partyDigest: digestC,
  });
  const initiatorPlan = planHandshakeV3NextAction(bothJoined, "INITIATOR");
  const validProposalInput = toolInputForAction(bothJoined, initiatorPlan, "INITIATOR");

  await assert.rejects(() => validateHandshakeV3ActionSubmission(bothJoined, {
    toolInput: {
      ...validProposalInput,
      action: {
        signingRequestId: validProposalInput.action.signingRequestId,
        signingDigest: validProposalInput.action.signingDigest,
        signerKeyId: validProposalInput.action.signerKeyId,
      },
    },
    expectedParty: agentParty("INITIATOR"),
    verifier: acceptingVerifier,
    now: "2026-08-29T20:00:01Z",
  }), { code: "SCHEMA_INVALID" });
  await assert.rejects(() => validateHandshakeV3ActionSubmission(bothJoined, {
    toolInput: { ...validProposalInput, expectedStateVersion: bothJoined.stateVersion - 1 },
    expectedParty: agentParty("INITIATOR"),
    verifier: acceptingVerifier,
    now: "2026-08-29T20:00:01Z",
  }), { code: "STATE_VERSION_CONFLICT" });
  await assert.rejects(() => validateHandshakeV3ActionSubmission(bothJoined, {
    toolInput: validProposalInput,
    expectedParty: agentParty("INITIATOR"),
    verifier: rejectingVerifier,
    now: "2026-08-29T20:00:01Z",
  }), { code: "SIGNATURE_INVALID" });
  let foreignVerifierCalls = 0;
  await assert.rejects(() => validateHandshakeV3ActionSubmission(bothJoined, {
    toolInput: validProposalInput,
    expectedParty: { ...agentParty("INITIATOR"), identityDigest: digestF },
    verifier: async () => {
      foreignVerifierCalls += 1;
      return true;
    },
    now: "2026-08-29T20:00:01Z",
  }), { code: "PRINCIPAL_DENIED" });
  await assert.rejects(() => validateHandshakeV3ActionSubmission({
    ...bothJoined,
    joinedPartyDigests: { ...bothJoined.joinedPartyDigests, INITIATOR: null },
  }, {
    toolInput: validProposalInput,
    expectedParty: agentParty("INITIATOR"),
    verifier: async () => {
      foreignVerifierCalls += 1;
      return true;
    },
    now: "2026-08-29T20:00:01Z",
  }), { code: "PRINCIPAL_DENIED" });
  assert.equal(foreignVerifierCalls, 0);
  await assert.rejects(() => validateHandshakeV3ActionSubmission(bothJoined, {
    toolInput: toolInputForAction(bothJoined, initiatorPlan, "RESPONDER"),
    expectedParty: agentParty("RESPONDER"),
    verifier: acceptingVerifier,
    now: "2026-08-29T20:00:01Z",
  }), { code: "ROLE_DENIED" });

  const proposalEvent = await validateHandshakeV3ActionSubmission(bothJoined, {
    toolInput: validProposalInput,
    expectedParty: agentParty("INITIATOR"),
    verifier: acceptingVerifier,
    now: "2026-08-29T20:00:01Z",
  });
  assert.equal(proposalEvent.expectedStateVersion, bothJoined.stateVersion);
  const proposalSubmitted = applyHandshakeV3ToolEvent(bothJoined, proposalEvent);
  const responderPlan = planHandshakeV3NextAction(proposalSubmitted, "RESPONDER");
  await assert.rejects(() => validateHandshakeV3ActionSubmission(proposalSubmitted, {
    toolInput: toolInputForAction(proposalSubmitted, responderPlan, "RESPONDER"),
    expectedParty: { ...agentParty("RESPONDER"), identityDigest: digestF },
    verifier: acceptingVerifier,
    now: "2026-08-29T20:00:02Z",
  }), { code: "PRINCIPAL_DENIED" });
  await assert.rejects(() => validateHandshakeV3ActionSubmission(proposalSubmitted, {
    toolInput: { ...toolInputForAction(proposalSubmitted, responderPlan, "RESPONDER"), expectedStateVersion: proposalSubmitted.stateVersion - 1 },
    expectedParty: agentParty("RESPONDER"),
    verifier: acceptingVerifier,
    now: "2026-08-29T20:00:02Z",
  }), { code: "STATE_VERSION_CONFLICT" });
  const acceptanceSubmitted = applyHandshakeV3ToolEvent(proposalSubmitted, await validateHandshakeV3ActionSubmission(proposalSubmitted, {
    toolInput: toolInputForAction(proposalSubmitted, responderPlan, "RESPONDER"),
    expectedParty: agentParty("RESPONDER"),
    verifier: acceptingVerifier,
    now: "2026-08-29T20:00:02Z",
  }));
  const checkpointPlan = planHandshakeV3NextAction(acceptanceSubmitted, "RESPONDER");
  await assert.rejects(() => validateHandshakeV3CheckpointSubmission(acceptanceSubmitted, {
    toolInput: toolInputForCheckpoint(acceptanceSubmitted, checkpointPlan),
    expectedParty: { ...agentParty("RESPONDER"), identityDigest: digestF },
    verifier: acceptingVerifier,
    now: "2026-08-29T20:00:03Z",
  }), { code: "PRINCIPAL_DENIED" });
  await assert.rejects(() => validateHandshakeV3CheckpointSubmission(acceptanceSubmitted, {
    toolInput: { ...toolInputForCheckpoint(acceptanceSubmitted, checkpointPlan), expectedStateVersion: acceptanceSubmitted.stateVersion - 1 },
    expectedParty: agentParty("RESPONDER"),
    verifier: acceptingVerifier,
    now: "2026-08-29T20:00:03Z",
  }), { code: "STATE_VERSION_CONFLICT" });
  await assert.rejects(() => validateHandshakeV3CheckpointSubmission(acceptanceSubmitted, {
    toolInput: toolInputForCheckpoint(acceptanceSubmitted, checkpointPlan),
    expectedParty: agentParty("RESPONDER"),
    verifier: rejectingVerifier,
    now: "2026-08-29T20:00:03Z",
  }), { code: "SIGNATURE_INVALID" });
});

test("draft.3 lifecycle helpers normalize hostile wrapper traps before callbacks", async () => {
  const base = createHandshakeV3Aggregate({
    sessionId: "sess_proxy_guard_012345",
    policy: policy(),
    expiresAt: "2026-08-29T21:00:00Z",
    statement: "proxy guard",
    createdAt: "2026-08-29T20:00:00Z",
  });
  await assertRejectsWithoutLeak(
    () => applyHandshakeV3ToolEvent(base, throwingGetterRecord("type")),
    "SCHEMA_INVALID",
  );
  await assertRejectsWithoutLeak(
    () => applyHandshakeV3ToolEvent(base, throwingOwnKeysProxy()),
    "SCHEMA_INVALID",
  );

  const accepted = applyHandshakeV3ToolEvent(base, {
    type: "INVITATION_ACCEPTED",
    expectedStateVersion: base.stateVersion,
    role: "RESPONDER",
    partyDigest: digestC,
  });
  const initiatorJoined = applyHandshakeV3ToolEvent(accepted, {
    type: "SESSION_JOINED",
    expectedStateVersion: accepted.stateVersion,
    role: "INITIATOR",
    partyDigest: digestB,
  });
  const bothJoined = applyHandshakeV3ToolEvent(initiatorJoined, {
    type: "SESSION_JOINED",
    expectedStateVersion: initiatorJoined.stateVersion,
    role: "RESPONDER",
    partyDigest: digestC,
  });
  let callbackCount = 0;
  const verifier = async () => {
    callbackCount += 1;
    return true;
  };
  await assertRejectsWithoutLeak(
    () => validateHandshakeV3ActionSubmission(bothJoined, throwingGetterRecord("toolInput")),
    "SCHEMA_INVALID",
  );
  await assertRejectsWithoutLeak(
    () => validateHandshakeV3ActionSubmission(bothJoined, throwingOwnKeysProxy()),
    "SCHEMA_INVALID",
  );
  await assertRejectsWithoutLeak(
    () => validateHandshakeV3ActionSubmission(bothJoined, {
      toolInput: toolInputForAction(bothJoined, planHandshakeV3NextAction(bothJoined, "INITIATOR"), "INITIATOR"),
      expectedParty: agentParty("INITIATOR"),
      get verifier() {
        throw new Error("secret raw verifier getter boom");
      },
      now: "2026-08-29T20:00:01Z",
    }),
    "SCHEMA_INVALID",
  );

  const proposalSubmitted = applyHandshakeV3ToolEvent(bothJoined, await validateHandshakeV3ActionSubmission(bothJoined, {
    toolInput: toolInputForAction(bothJoined, planHandshakeV3NextAction(bothJoined, "INITIATOR"), "INITIATOR"),
    expectedParty: agentParty("INITIATOR"),
    verifier,
    now: "2026-08-29T20:00:01Z",
  }));
  const acceptanceSubmitted = applyHandshakeV3ToolEvent(proposalSubmitted, await validateHandshakeV3ActionSubmission(proposalSubmitted, {
    toolInput: toolInputForAction(proposalSubmitted, planHandshakeV3NextAction(proposalSubmitted, "RESPONDER"), "RESPONDER"),
    expectedParty: agentParty("RESPONDER"),
    verifier,
    now: "2026-08-29T20:00:02Z",
  }));
  await assertRejectsWithoutLeak(
    () => validateHandshakeV3CheckpointSubmission(acceptanceSubmitted, throwingGetterRecord("toolInput")),
    "SCHEMA_INVALID",
  );
  await assertRejectsWithoutLeak(
    () => validateHandshakeV3CheckpointSubmission(acceptanceSubmitted, throwingOwnKeysProxy()),
    "SCHEMA_INVALID",
  );
  assert.equal(callbackCount, 2);
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
  assert.deepEqual(createHandshakeV3RoleGrantRecoveryAuditEvent(roleGrant(), recovered.roleGrant, {
    occurredAt: "2026-08-29T20:30:00Z",
  }), {
    schema: "clockchain.handshake-v3-role-grant-recovery/v1",
    type: "ROLE_GRANT_RECOVERED",
    sessionId: "sess_0123456789abcdef",
    role: "INITIATOR",
    invalidatedRoleGrantId: "grant_0123456789abcdef",
    replacementRoleGrantId: "grant_recovered_123",
    principalDigest: digestB,
    proofKeyThumbprint: digestC,
    occurredAt: "2026-08-29T20:30:00Z",
  });
  assert.throws(() => createHandshakeV3RoleGrantRecoveryAuditEvent(roleGrant(), {
    ...recovered.roleGrant,
    principalDigest: digestA,
  }, { occurredAt: "2026-08-29T20:30:00Z" }), { code: "PRINCIPAL_DENIED" });
  assert.throws(() => recoverHandshakeV3RoleGrant(roleGrant(), {
    roleGrantId: "grant_recovered_456",
    principalDigest: digestB,
    proofKeyThumbprint: digestC,
    now: "2026-08-29T20:30:00Z",
    session: { ...original, sessionId: "sess_mismatched_123" },
  }), { code: "ROLE_DENIED" });
  assert.throws(() => recoverHandshakeV3RoleGrant(roleGrant(), {
    roleGrantId: "grant_recovered_789",
    principalDigest: digestB,
    proofKeyThumbprint: digestC,
    now: "2026-08-29T20:30:00Z",
    session: { ...original, role: "RESPONDER" },
  }), { code: "ROLE_DENIED" });
  assert.throws(() => recoverHandshakeV3RoleGrant({
    ...roleGrant(),
    expiresAt: "2026-08-29T20:00:60Z",
  }, {
    roleGrantId: "grant_recovered_999",
    principalDigest: digestB,
    proofKeyThumbprint: digestC,
    now: "2026-08-29T20:01:00Z",
    session: original,
  }), { code: "TOKEN_EXPIRED" });
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

  const minimalRequest = createHandshakeV3SigningRequest({
    signingRequestId: "signreq_minimal_0123456",
    actionType: "PROPOSAL",
    sessionId: "sess_0123456789abcdef",
    stateVersion: 4,
    role: "INITIATOR",
    policyDigest: digestA,
    statementDigest: digestB,
    nonce: "nonce_minimal_0123456",
    issuedAt: "2026-08-29T20:00:00Z",
    expiresAt: "2026-08-29T20:05:00Z",
  });
  assert.equal(Object.hasOwn(minimalRequest, "counterpartIdentityDigest"), false);
  assert.equal(Object.hasOwn(minimalRequest, "priorActionDigest"), false);
  assert.equal(Object.hasOwn(minimalRequest, "evidenceDigest"), false);

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
    expectedParty: {
      identityDigest: digestB,
      role: "INITIATOR",
      signingKeyId: "agent-a-key",
      signingAlgorithm: "EdDSA",
      publicKey: "p".repeat(32),
    },
    expectedSigningRequestId: request.signingRequestId,
    expectedSigningDigest: request.signingDigest,
    now: "2026-08-29T20:01:00Z",
    verifier: async ({ publicKey, algorithm, keyId, signingDigest }) => {
      calls += 1;
      return publicKey === "p".repeat(32) && algorithm === "EdDSA" && keyId === "agent-a-key" && signingDigest === request.signingDigest;
    },
  });
  assert.equal(calls, 1);
  await assert.rejects(() => verifyHandshakeV3SignedAction({
    request,
    action,
    expectedParty: {
      identityDigest: digestB,
      role: "INITIATOR",
      signingKeyId: "agent-a-key",
      signingAlgorithm: "EdDSA",
      publicKey: "q".repeat(32),
    },
    expectedSigningRequestId: request.signingRequestId,
    expectedSigningDigest: request.signingDigest,
    now: "2026-08-29T20:01:00Z",
    verifier: async ({ publicKey, keyId }) => publicKey === "p".repeat(32) && keyId === "agent-a-key",
  }), { code: "SIGNATURE_INVALID" });
  await assert.rejects(() => verifyHandshakeV3SignedAction({
    request,
    action: { ...action, signingDigest: digestF },
    expectedParty: {
      identityDigest: digestB,
      role: "INITIATOR",
      signingKeyId: "agent-a-key",
      signingAlgorithm: "EdDSA",
      publicKey: "p".repeat(32),
    },
    now: "2026-08-29T20:01:00Z",
    verifier: async () => {
      throw new Error("must not call");
    },
  }), { code: "SIGNATURE_INVALID" });
  await assert.rejects(() => verifyHandshakeV3SignedAction({
    request: { ...request, signingDigest: digestF },
    action: { ...action, signingDigest: digestF },
    expectedParty: {
      identityDigest: digestB,
      role: "INITIATOR",
      signingKeyId: "agent-a-key",
      signingAlgorithm: "EdDSA",
      publicKey: "p".repeat(32),
    },
    now: "2026-08-29T20:01:00Z",
    verifier: async () => {
      throw new Error("must not call");
    },
  }), { code: "SIGNATURE_INVALID" });
  await assert.rejects(() => verifyHandshakeV3SignedAction({
    request,
    action: { ...action, algorithm: "ES256K" },
    expectedParty: {
      identityDigest: digestB,
      role: "INITIATOR",
      signingKeyId: "agent-a-key",
      signingAlgorithm: "EdDSA",
      publicKey: "p".repeat(32),
    },
    now: "2026-08-29T20:01:00Z",
    verifier: async () => {
      throw new Error("must not call");
    },
  }), { code: "SIGNATURE_INVALID" });
  await assert.rejects(() => verifyHandshakeV3SignedAction({
    request,
    action,
    expectedParty: {
      identityDigest: digestB,
      role: "INITIATOR",
      signingKeyId: "agent-a-key",
      signingAlgorithm: "EdDSA",
      publicKey: "p".repeat(32),
    },
    now: "2026-08-29T19:59:59Z",
    verifier: async () => {
      throw new Error("must not call");
    },
  }), { code: "SIGNATURE_INVALID" });
  await assertRejectsWithoutLeak(() => verifyHandshakeV3SignedAction({
    request,
    action,
    expectedParty: {
      identityDigest: digestB,
      role: "INITIATOR",
      signingKeyId: "agent-a-key",
      signingAlgorithm: "EdDSA",
      publicKey: "p".repeat(32),
    },
    now: "2026-08-29T20:01:00Z",
    verifier: async () => {
      throw new Error("secret verifier callback boom");
    },
  }), "SIGNATURE_INVALID");

  for (const [badRequest, badNow] of [
    [createHandshakeV3SigningRequest({
      signingRequestId: "signreq_leap_notyet",
      actionType: "PROPOSAL",
      sessionId: "sess_0123456789abcdef",
      stateVersion: 4,
      role: "INITIATOR",
      policyDigest: digestA,
      statementDigest: digestB,
      nonce: "nonce_leap_notyet",
      issuedAt: "2026-08-29T20:00:60Z",
      expiresAt: "2026-08-29T20:05:00Z",
    }), "2026-08-29T20:00:59.999Z"],
    [createHandshakeV3SigningRequest({
      signingRequestId: "signreq_leap_expired",
      actionType: "PROPOSAL",
      sessionId: "sess_0123456789abcdef",
      stateVersion: 4,
      role: "INITIATOR",
      policyDigest: digestA,
      statementDigest: digestB,
      nonce: "nonce_leap_expired",
      issuedAt: "2026-08-29T20:00:00Z",
      expiresAt: "2026-08-29T20:00:60Z",
    }), "2026-08-29T20:01:00Z"],
  ]) {
    let verifierCalled = false;
    await assert.rejects(() => verifyHandshakeV3SignedAction({
      request: badRequest,
      action: {
        ...action,
        signingRequestId: badRequest.signingRequestId,
        signingDigest: badRequest.signingDigest,
      },
      expectedParty: {
        identityDigest: digestB,
        role: "INITIATOR",
        signingKeyId: "agent-a-key",
        signingAlgorithm: "EdDSA",
        publicKey: "p".repeat(32),
      },
      now: badNow,
      verifier: async () => {
        verifierCalled = true;
        return true;
      },
    }), { code: "SIGNATURE_INVALID" });
    assert.equal(verifierCalled, false);
  }
});

test("leap-second time windows fail closed before security side effects", async () => {
  for (const badCert of [
    signedCertificate({ issuedAt: "2026-08-29T20:00:60Z", expiresAt: "2026-08-29T21:00:00Z" }),
    signedCertificate({ expiresAt: "2026-08-29T20:00:60Z" }),
  ]) {
    const certificateSideEffects = [];
    await assert.rejects(() => verifyHandshakeV3Certificate({
      certificate: badCert,
      expectedCertificateDigest: badCert.certificateDigest,
      expectedPolicyDigest: badCert.policyDigest,
      expectedPartyDigests: badCert.partyDigests,
      now: badCert.expiresAt === "2026-08-29T20:00:60Z" ? "2026-08-29T20:01:00Z" : "2026-08-29T20:00:59.999Z",
      verifyIssuerSignature: async () => {
        certificateSideEffects.push("signature");
        return true;
      },
      getRevocationStatus: async () => {
        certificateSideEffects.push("revocation");
        return "GOOD";
      },
    }), { code: "RESULT_VERIFICATION_FAILED" });
    assert.deepEqual(certificateSideEffects, []);

    const sideEffects = [];
    await assert.rejects(() => verifyHandshakeV3Continuation({
      certificate: badCert,
      continuation: continuation(badCert),
      expectedPartyRoleDigests: badCert.partyDigests,
      now: badCert.expiresAt === "2026-08-29T20:00:60Z" ? "2026-08-29T20:01:00Z" : "2026-08-29T20:00:59.999Z",
      verifyIssuerSignature: async () => {
        sideEffects.push("signature");
        return true;
      },
      getRevocationStatus: async () => {
        sideEffects.push("revocation");
        return "GOOD";
      },
      checkAndRecordReplay: async () => {
        sideEffects.push("replay");
        return true;
      },
    }), { code: "RESULT_VERIFICATION_FAILED" });
    assert.deepEqual(sideEffects, []);
  }

  const cert = certificate();
  for (const [badCont, badNow] of [
    [{ ...continuation(cert), notBefore: "2026-08-29T20:00:60Z" }, "2026-08-29T20:00:59.999Z"],
    [{ ...continuation(cert), expiresAt: "2026-08-29T20:00:60Z" }, "2026-08-29T20:01:00Z"],
  ]) {
    const sideEffects = [];
    await assert.rejects(() => verifyHandshakeV3Continuation({
      certificate: cert,
      continuation: badCont,
      expectedPartyRoleDigests: badCont.partyRoleDigests,
      now: badNow,
      verifyIssuerSignature: async () => {
        sideEffects.push("signature");
        return true;
      },
      getRevocationStatus: async () => {
        sideEffects.push("revocation");
        return "GOOD";
      },
      checkAndRecordReplay: async () => {
        sideEffects.push("replay");
        return true;
      },
    }), { code: "RESULT_VERIFICATION_FAILED" });
    assert.deepEqual(sideEffects, []);
  }
});

test("external callback throws normalize to stable v3 error codes without leaking messages", async () => {
  const cert = certificate();
  const cont = continuation(cert);

  await assertRejectsWithoutLeak(() => verifyHandshakeV3Certificate({
    certificate: cert,
    expectedCertificateDigest: cert.certificateDigest,
    expectedPolicyDigest: cert.policyDigest,
    expectedPartyDigests: cert.partyDigests,
    now: "2026-08-29T20:10:00Z",
    verifyIssuerSignature: async () => {
      throw new Error("secret certificate signature callback boom");
    },
    getRevocationStatus: async () => "GOOD",
  }), "SIGNATURE_INVALID");

  await assertRejectsWithoutLeak(() => verifyHandshakeV3Certificate({
    certificate: cert,
    expectedCertificateDigest: cert.certificateDigest,
    expectedPolicyDigest: cert.policyDigest,
    expectedPartyDigests: cert.partyDigests,
    now: "2026-08-29T20:10:00Z",
    verifyIssuerSignature: async () => true,
    getRevocationStatus: async () => {
      throw new Error("secret certificate revocation callback boom");
    },
  }), "RESULT_VERIFICATION_FAILED");

  for (const throwingSignatureIndex of [0, 1]) {
    let signatureCalls = 0;
    await assertRejectsWithoutLeak(() => verifyHandshakeV3Continuation({
      certificate: cert,
      continuation: cont,
      expectedPartyRoleDigests: cont.partyRoleDigests,
      now: "2026-08-29T20:10:00Z",
      verifyIssuerSignature: async () => {
        if (signatureCalls++ === throwingSignatureIndex) {
          throw new Error("secret continuation signature callback boom");
        }
        return true;
      },
      getRevocationStatus: async () => "GOOD",
      checkAndRecordReplay: async () => true,
    }), "SIGNATURE_INVALID");
  }

  for (const throwingRevocationIndex of [0, 1]) {
    let revocationCalls = 0;
    await assertRejectsWithoutLeak(() => verifyHandshakeV3Continuation({
      certificate: cert,
      continuation: cont,
      expectedPartyRoleDigests: cont.partyRoleDigests,
      now: "2026-08-29T20:10:00Z",
      verifyIssuerSignature: async () => true,
      getRevocationStatus: async () => {
        if (revocationCalls++ === throwingRevocationIndex) {
          throw new Error("secret revocation callback boom");
        }
        return "GOOD";
      },
      checkAndRecordReplay: async () => true,
    }), "RESULT_VERIFICATION_FAILED");
  }

  await assertRejectsWithoutLeak(() => verifyHandshakeV3Continuation({
    certificate: cert,
    continuation: cont,
    expectedPartyRoleDigests: cont.partyRoleDigests,
    now: "2026-08-29T20:10:00Z",
    verifyIssuerSignature: async () => true,
    getRevocationStatus: async () => "GOOD",
    checkAndRecordReplay: async () => {
      throw new Error("secret replay callback boom");
    },
  }), "RESULT_VERIFICATION_FAILED");
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
  assert.deepEqual(calls.map(([name]) => name), ["signature", "signature", "revocation", "revocation", "replay"]);

  const noReplayCalls = [];
  await assert.rejects(() => verifyHandshakeV3Continuation({
    certificate: cert,
    continuation: cont,
    expectedPartyRoleDigests: cont.partyRoleDigests,
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

  const independentInput = validateHandshakeV3ToolInput("agent_handshake_result_verify", {
    certificate: cert,
    continuation: cont,
  });
  const independentlyVerified = await verifyHandshakeV3Continuation({
    ...independentInput.input,
    now: "2026-08-29T20:10:00Z",
    verifyIssuerSignature: async () => true,
    getRevocationStatus: async () => "GOOD",
    checkAndRecordReplay: async () => true,
  });
  assert.equal(independentlyVerified.valid, true);

  const mismatchSideEffects = [];
  await assert.rejects(() => verifyHandshakeV3Continuation({
    certificate: cert,
    continuation: cont,
    expectedPartyRoleDigests: [digestA, digestB],
    now: "2026-08-29T20:10:00Z",
    verifyIssuerSignature: async () => {
      mismatchSideEffects.push("signature");
      return true;
    },
    getRevocationStatus: async () => {
      mismatchSideEffects.push("revocation");
      return "GOOD";
    },
    checkAndRecordReplay: async () => {
      mismatchSideEffects.push("replay");
      return true;
    },
  }), { code: "ROLE_DENIED" });
  assert.deepEqual(mismatchSideEffects, []);

  for (const badContinuation of [
    { ...cont, sessionId: "sess_mismatch_123456" },
    { ...cont, certificateDigest: digestF },
    { ...cont, policyDigest: digestF },
    { ...cont, partyRoleDigests: [digestF, digestE] },
    { ...cont, clockchainNetwork: "mainnet" },
    { ...cont, trustRootId: "other-root" },
    { ...cont, allowedNextActionClass: "UNRELATED_BUSINESS_ACTION" },
  ]) {
    const sideEffects = [];
    await assert.rejects(() => verifyHandshakeV3Continuation({
      certificate: cert,
      continuation: badContinuation,
      expectedPartyRoleDigests: cont.partyRoleDigests,
      now: "2026-08-29T20:10:00Z",
      verifyIssuerSignature: async () => {
        sideEffects.push("signature");
        return true;
      },
      getRevocationStatus: async () => {
        sideEffects.push("revocation");
        return "GOOD";
      },
      checkAndRecordReplay: async () => {
        sideEffects.push("replay");
        return true;
      },
    }), { code: "RESULT_VERIFICATION_FAILED" });
    assert.deepEqual(sideEffects, []);
  }

  for (const badCertificate of [
    { ...cert, expiresAt: "2026-08-29T20:05:00Z" },
  ]) {
    const sideEffects = [];
    await assert.rejects(() => verifyHandshakeV3Continuation({
      certificate: badCertificate,
      continuation: cont,
      expectedPartyRoleDigests: cont.partyRoleDigests,
      now: "2026-08-29T20:10:00Z",
      verifyIssuerSignature: async () => {
        sideEffects.push("signature");
        return true;
      },
      getRevocationStatus: async () => {
        sideEffects.push("revocation");
        return "GOOD";
      },
      checkAndRecordReplay: async () => {
        sideEffects.push("replay");
        return true;
      },
    }), { code: "RESULT_VERIFICATION_FAILED" });
    assert.deepEqual(sideEffects, []);
  }

  const revokedSideEffects = [];
  await assert.rejects(() => verifyHandshakeV3Continuation({
    certificate: cert,
    continuation: cont,
    expectedPartyRoleDigests: cont.partyRoleDigests,
    now: "2026-08-29T20:10:00Z",
    verifyIssuerSignature: async () => {
      revokedSideEffects.push("signature");
      return true;
    },
    getRevocationStatus: async (handle) => {
      revokedSideEffects.push(["revocation", handle]);
      return handle === cert.certificateId ? "REVOKED" : "GOOD";
    },
    checkAndRecordReplay: async () => {
      revokedSideEffects.push("replay");
      return true;
    },
  }), { code: "SESSION_REVOKED" });
  assert.deepEqual(revokedSideEffects, ["signature", "signature", ["revocation", cert.certificateId]]);

  const loopholeSideEffects = [];
  await assert.rejects(() => verifyHandshakeV3Continuation({
    certificate: { ...cert, partyDigests: [digestB, digestD] },
    continuation: cont,
    now: "2026-08-29T20:10:00Z",
    verifyIssuerSignature: async () => {
      loopholeSideEffects.push("signature");
      return true;
    },
    getRevocationStatus: async () => {
      loopholeSideEffects.push("revocation");
      return "GOOD";
    },
    checkAndRecordReplay: async () => {
      loopholeSideEffects.push("replay");
      return true;
    },
  }), { code: "RESULT_VERIFICATION_FAILED" });
  assert.deepEqual(loopholeSideEffects, []);

});
