import {
  HANDSHAKE_V3_ALLOWED_TRANSITIONS_BY_STATE,
  HANDSHAKE_V3_NONTERMINAL_STATES,
  HANDSHAKE_V3_SCHEMA_VERSION,
  HANDSHAKE_V3_TERMINAL_STATES,
  fail,
} from "./constants.mjs";
import { handshakeV3Digest } from "./canonical.mjs";
import { createHandshakeV3SigningRequest, verifyHandshakeV3SignedAction } from "./signing.mjs";
import { validateHandshakeV3Party, validateHandshakeV3Session, validateHandshakeV3ToolInput, validateHandshakeV3ToolResult } from "./validators.mjs";

const HAPPY_PATH = Object.freeze({
  INVITED: { CLAIM_INVITATION: ["RESPONDER", "CLAIMED"] },
  CLAIMED: { PREPARE_POLICY: ["INITIATOR", "POLICY_READY"] },
  POLICY_READY: { BIND_PARTIES: ["INITIATOR", "PARTIES_BOUND"] },
  PARTIES_BOUND: { SUBMIT_PROPOSAL: ["INITIATOR", "PROPOSAL_PENDING"] },
  PROPOSAL_PENDING: { SUBMIT_ACCEPTANCE: ["RESPONDER", "ACCEPTANCE_PENDING"] },
  ACCEPTANCE_PENDING: { CONFIRM_ANCHOR: ["CLOCKCHAIN", "ANCHORING"] },
  ANCHORING: { ISSUE_CERTIFICATE: ["CLOCKCHAIN", "CERTIFICATE_ISSUED"] },
  CERTIFICATE_ISSUED: { ISSUE_CONTINUATION: ["CLOCKCHAIN", "CONTINUATION_ISSUED"] },
  CONTINUATION_ISSUED: { COMPLETE: ["CLOCKCHAIN", "COMPLETED"] },
});

const TERMINAL_ACTIONS = Object.freeze({
  FAIL_CLOSED: [["SYSTEM"], "FAILED_CLOSED"],
  CANCEL: [["INITIATOR", "RESPONDER"], "CANCELLED"],
  EXPIRE: [["SYSTEM"], "EXPIRED"],
  REVOKE: [["CLOCKCHAIN"], "REVOKED"],
});

function nextTransitions(state) {
  return [...(HANDSHAKE_V3_ALLOWED_TRANSITIONS_BY_STATE[state] ?? [])];
}

function normalizeSession(session) {
  return validateHandshakeV3Session({
    ...session,
    allowedTransitions: session.allowedTransitions ?? nextTransitions(session.state),
  });
}

function denied(session, code) {
  return Object.freeze({ allowed: false, error: Object.freeze({ code }), session });
}

function advanced(session, state) {
  return Object.freeze({
    allowed: true,
    session: normalizeSession({
      ...session,
      state,
      stateVersion: session.stateVersion + 1,
      allowedTransitions: nextTransitions(state),
    }),
  });
}

export function applyHandshakeV3Transition(inputSession, transition) {
  const session = normalizeSession(inputSession);
  if (transition.expectedStateVersion !== session.stateVersion) return denied(session, "STATE_VERSION_CONFLICT");
  if (session.state === "COMPLETED") {
    if (transition.actionType === "REVOKE" && transition.actor === "CLOCKCHAIN") return advanced(session, "REVOKED");
    return denied(session, "TRANSITION_DENIED");
  }
  if (HANDSHAKE_V3_TERMINAL_STATES.includes(session.state)) return denied(session, "TRANSITION_DENIED");
  if (TERMINAL_ACTIONS[transition.actionType]) {
    const [actors, nextState] = TERMINAL_ACTIONS[transition.actionType];
    if (!actors.includes(transition.actor)) return denied(session, "ROLE_DENIED");
    return advanced(session, nextState);
  }
  const allowed = HAPPY_PATH[session.state]?.[transition.actionType];
  if (!allowed) return denied(session, "TRANSITION_DENIED");
  const [actor, nextState] = allowed;
  if (transition.actor !== actor) return denied(session, "ROLE_DENIED");
  return advanced(session, nextState);
}

export function evaluateHandshakeV3OperatorRequest(inputSession, request) {
  const session = normalizeSession(inputSession);
  if (!["REQUEST_EXPIRY_EVALUATION", "REQUEST_CANCELLATION"].includes(request.action)) fail("SCHEMA_INVALID");
  if (request.observedStateVersion !== session.stateVersion) {
    return Object.freeze({ accepted: false, requestOnly: true, session, denialCode: "STATE_VERSION_CONFLICT" });
  }
  return Object.freeze({
    accepted: HANDSHAKE_V3_NONTERMINAL_STATES.includes(session.state),
    requestOnly: true,
    session,
    ...(HANDSHAKE_V3_NONTERMINAL_STATES.includes(session.state) ? {} : { denialCode: "TERMINAL" }),
  });
}

export function createHandshakeV3PolicyDigest(policy) {
  return handshakeV3Digest({
    schemaVersion: HANDSHAKE_V3_SCHEMA_VERSION,
    kind: "policy",
    policy,
  });
}

export function createHandshakeV3StatementDigest(statement) {
  if (typeof statement !== "string" || statement.length === 0 || statement.length > 8192) fail("SCHEMA_INVALID");
  return handshakeV3Digest({
    schemaVersion: HANDSHAKE_V3_SCHEMA_VERSION,
    kind: "statement",
    statement,
  });
}

function aggregateEventDigest(aggregate) {
  return handshakeV3Digest({
    schemaVersion: HANDSHAKE_V3_SCHEMA_VERSION,
    kind: "aggregate-event-chain",
    sessionId: aggregate.sessionId,
    state: aggregate.state,
    stateVersion: aggregate.stateVersion,
    joinedPartyDigests: aggregate.joinedPartyDigests,
    submittedActionDigests: aggregate.submittedActionDigests,
    certificateDigest: aggregate.certificateDigest ?? null,
    continuationDigest: aggregate.continuationDigest ?? null,
  });
}

function plannedSigningRequest(aggregate, actionType, role) {
  return createHandshakeV3SigningRequest({
    signingRequestId: `signreq.${aggregate.sessionId}.${aggregate.stateVersion}.${actionType.toLowerCase()}`,
    actionType,
    sessionId: aggregate.sessionId,
    stateVersion: aggregate.stateVersion,
    role,
    policyDigest: aggregate.policyDigest,
    statementDigest: aggregate.statementDigest,
    priorActionDigest: aggregate.submittedActionDigests.at(-1),
    nonce: `nonce.${aggregate.sessionId}.${aggregate.stateVersion}.${actionType.toLowerCase()}`,
    issuedAt: aggregate.updatedAt,
    expiresAt: aggregate.expiresAt,
  });
}

function normalizeAggregate(input) {
  const aggregate = {
    schemaVersion: HANDSHAKE_V3_SCHEMA_VERSION,
    state: input.state ?? "INVITED",
    stateVersion: input.stateVersion ?? 0,
    joinedPartyDigests: { INITIATOR: null, RESPONDER: null, ...(input.joinedPartyDigests ?? {}) },
    submittedActionDigests: [...(input.submittedActionDigests ?? [])],
    externalBusinessActionPerformed: false,
    ...input,
  };
  aggregate.policyDigest ??= createHandshakeV3PolicyDigest(aggregate.policy);
  aggregate.statementDigest ??= createHandshakeV3StatementDigest(aggregate.statement);
  aggregate.eventCursor ??= "cursor.initial.000";
  aggregate.createdAt ??= aggregate.updatedAt ?? aggregate.expiresAt;
  aggregate.updatedAt ??= aggregate.createdAt;
  aggregate.eventChainDigest = aggregateEventDigest(aggregate);
  return Object.freeze({
    ...aggregate,
    joinedPartyDigests: Object.freeze({ ...aggregate.joinedPartyDigests }),
    submittedActionDigests: Object.freeze([...aggregate.submittedActionDigests]),
  });
}

export function createHandshakeV3Aggregate(input) {
  if (!input?.sessionId || !input?.policy || !input?.expiresAt || !input?.statement) fail("SCHEMA_INVALID");
  return normalizeAggregate(input);
}

export function projectHandshakeV3SessionForRole(aggregateInput, role) {
  const aggregate = normalizeAggregate(aggregateInput);
  if (!["INITIATOR", "RESPONDER"].includes(role)) fail("ROLE_DENIED");
  const partyDigests = Object.values(aggregate.joinedPartyDigests).filter(Boolean);
  const session = {
    sessionId: aggregate.sessionId,
    role,
    state: aggregate.state,
    stateVersion: aggregate.stateVersion,
    policy: aggregate.policy,
    policyDigest: aggregate.policyDigest,
    ...(partyDigests.length > 0 ? { partyDigests } : {}),
    expiresAt: aggregate.expiresAt,
    allowedTransitions: nextTransitions(aggregate.state),
    eventCursor: aggregate.eventCursor,
  };
  if (aggregate.pendingSigningRequest?.role === role) {
    session.pendingSigningRequest = aggregate.pendingSigningRequest;
  }
  return validateHandshakeV3Session(session);
}

function waitPlan(aggregate, role, waitingOn, requiredTool = "agent_handshake_session_next", changed = false, events = []) {
  return validateHandshakeV3ToolResult("agent_handshake_session_next", {
    changed,
    nextAction: "WAIT",
    session: projectHandshakeV3SessionForRole(aggregate, role),
    events,
    retryAfterMs: 1000,
    waitingOn,
    requiredTool,
    expectedStateVersion: aggregate.stateVersion,
  });
}

export function planHandshakeV3NextAction(aggregateInput, role, options = {}) {
  const aggregate = normalizeAggregate(aggregateInput);
  const joined = aggregate.joinedPartyDigests[role];
  if (!joined && (role === "INITIATOR" || aggregate.state === "CLAIMED")) {
    return validateHandshakeV3ToolResult("agent_handshake_session_next", {
      changed: options.changed === true,
      nextAction: "JOIN_SESSION",
      session: projectHandshakeV3SessionForRole(aggregate, role),
      events: options.events ?? [],
      retryAfterMs: 0,
      waitingOn: "SELF",
      requiredTool: "agent_handshake_session_join",
      expectedStateVersion: aggregate.stateVersion,
    });
  }
  if (aggregate.pendingSigningRequest?.role === role) {
    const action = aggregate.pendingSigningRequest.actionType === "EVIDENCE" ? "SUBMIT_CHECKPOINT" : "SIGN_AND_SUBMIT";
    return validateHandshakeV3ToolResult("agent_handshake_session_next", {
      changed: true,
      nextAction: action,
      session: projectHandshakeV3SessionForRole(aggregate, role),
      events: options.events ?? [],
      retryAfterMs: 0,
      waitingOn: "SELF",
      requiredTool: action === "SUBMIT_CHECKPOINT"
        ? "agent_handshake_session_submit_checkpoint"
        : "agent_handshake_session_submit",
      expectedStateVersion: aggregate.stateVersion,
    });
  }
  if (aggregate.state === "CONTINUATION_ISSUED" || aggregate.state === "COMPLETED") {
    return validateHandshakeV3ToolResult("agent_handshake_session_next", {
      changed: options.changed === true,
      nextAction: "FETCH_RESULT",
      session: projectHandshakeV3SessionForRole(aggregate, role),
      events: options.events ?? [],
      retryAfterMs: 0,
      waitingOn: "CALLER_VERIFICATION",
      requiredTool: "agent_handshake_session_get_result",
      expectedStateVersion: aggregate.stateVersion,
    });
  }
  if (HANDSHAKE_V3_TERMINAL_STATES.includes(aggregate.state)) {
    return validateHandshakeV3ToolResult("agent_handshake_session_next", {
      changed: options.changed === true,
      nextAction: "TERMINAL",
      session: projectHandshakeV3SessionForRole(aggregate, role),
      events: options.events ?? [],
      retryAfterMs: 0,
      waitingOn: "NONE",
      requiredTool: "agent_handshake_audit_receipt",
      expectedStateVersion: aggregate.stateVersion,
    });
  }
  const waitingOn = aggregate.state === "CERTIFICATE_ISSUED" || aggregate.state === "ANCHORING"
    ? "CLOCKCHAIN"
    : "COUNTERPARTY";
  return waitPlan(
    aggregate,
    role,
    waitingOn,
    waitingOn === "CLOCKCHAIN" ? "agent_handshake_session_get_result" : "agent_handshake_session_next",
    options.changed === true,
    options.events ?? [],
  );
}

function advanceAggregate(input, patch) {
  return normalizeAggregate({
    ...input,
    ...patch,
    stateVersion: input.stateVersion + 1,
    updatedAt: patch.occurredAt ?? input.updatedAt,
    externalBusinessActionPerformed: false,
  });
}

function assertExpectedStateVersion(aggregate, expectedStateVersion) {
  if (!Number.isInteger(expectedStateVersion) || expectedStateVersion < 0) fail("SCHEMA_INVALID");
  if (expectedStateVersion !== aggregate.stateVersion) fail("STATE_VERSION_CONFLICT");
}

function assertEventState(aggregate, states) {
  if (!states.includes(aggregate.state)) fail("TRANSITION_DENIED");
}

function assertDigest(value) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value)) fail("SCHEMA_INVALID");
}

function assertPendingRequest(aggregate, { role, actionType }) {
  const request = aggregate.pendingSigningRequest;
  if (!request) fail("TRANSITION_DENIED");
  if (request.role !== role) fail("ROLE_DENIED");
  if (request.actionType !== actionType) fail("TRANSITION_DENIED");
  if (request.sessionId !== aggregate.sessionId || request.stateVersion !== aggregate.stateVersion) fail("STATE_VERSION_CONFLICT");
  if (request.policyDigest !== aggregate.policyDigest || request.statementDigest !== aggregate.statementDigest) fail("POLICY_DIGEST_MISMATCH");
  return request;
}

function snapshotTopLevelRecord(value, allowedKeys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("SCHEMA_INVALID");
  const allowed = new Set(allowedKeys);
  const snapshot = {};
  let keys;
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    fail("SCHEMA_INVALID");
  }
  for (const key of keys) {
    if (typeof key !== "string") fail("SCHEMA_INVALID");
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      fail("SCHEMA_INVALID");
    }
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail("SCHEMA_INVALID");
    if (allowed.has(key)) snapshot[key] = descriptor.value;
  }
  return Object.freeze(snapshot);
}

const TOOL_EVENT_KEYS = Object.freeze([
  "type",
  "expectedStateVersion",
  "role",
  "partyDigest",
  "eventCursor",
  "actionType",
  "signingDigest",
  "certificateDigest",
  "continuationDigest",
  "occurredAt",
]);

const SUBMISSION_WRAPPER_KEYS = Object.freeze([
  "toolInput",
  "expectedParty",
  "verifier",
  "now",
  "eventCursor",
]);

export function applyHandshakeV3ToolEvent(aggregateInput, event) {
  const aggregate = normalizeAggregate(aggregateInput);
  const safeEvent = snapshotTopLevelRecord(event, TOOL_EVENT_KEYS);
  if (!safeEvent.type) fail("SCHEMA_INVALID");
  assertExpectedStateVersion(aggregate, safeEvent.expectedStateVersion);
  if (safeEvent.type === "INVITATION_ACCEPTED") {
    assertEventState(aggregate, ["INVITED"]);
    if (safeEvent.role !== "RESPONDER") fail("ROLE_DENIED");
    if (safeEvent.partyDigest !== undefined) assertDigest(safeEvent.partyDigest);
    return advanceAggregate(aggregate, { state: "CLAIMED", eventCursor: safeEvent.eventCursor ?? aggregate.eventCursor });
  }
  if (safeEvent.type === "SESSION_JOINED") {
    if (!["INITIATOR", "RESPONDER"].includes(safeEvent.role) || !safeEvent.partyDigest) fail("SCHEMA_INVALID");
    assertDigest(safeEvent.partyDigest);
    assertEventState(aggregate, ["INVITED", "CLAIMED"]);
    if (safeEvent.role === "RESPONDER" && aggregate.state !== "CLAIMED") fail("TRANSITION_DENIED");
    if (aggregate.joinedPartyDigests[safeEvent.role]) {
      if (aggregate.joinedPartyDigests[safeEvent.role] === safeEvent.partyDigest) return aggregate;
      fail("IDEMPOTENCY_CONFLICT");
    }
    const joinedPartyDigests = { ...aggregate.joinedPartyDigests, [safeEvent.role]: safeEvent.partyDigest };
    if (joinedPartyDigests.INITIATOR && joinedPartyDigests.RESPONDER) {
      const provisional = advanceAggregate(aggregate, {
        state: "PARTIES_BOUND",
        joinedPartyDigests,
        eventCursor: safeEvent.eventCursor ?? aggregate.eventCursor,
      });
      return normalizeAggregate({
        ...provisional,
        pendingSigningRequest: plannedSigningRequest(provisional, "PROPOSAL", "INITIATOR"),
      });
    }
    return advanceAggregate(aggregate, { joinedPartyDigests, eventCursor: safeEvent.eventCursor ?? aggregate.eventCursor });
  }
  if (safeEvent.type === "ACTION_SUBMITTED") {
    if (!["INITIATOR", "RESPONDER"].includes(safeEvent.role)) fail("SCHEMA_INVALID");
    assertDigest(safeEvent.signingDigest);
    const required = safeEvent.actionType === "PROPOSAL"
      ? { state: "PARTIES_BOUND", role: "INITIATOR" }
      : safeEvent.actionType === "ACCEPTANCE"
        ? { state: "PROPOSAL_PENDING", role: "RESPONDER" }
        : null;
    if (!required) fail("TRANSITION_DENIED");
    assertEventState(aggregate, [required.state]);
    const request = assertPendingRequest(aggregate, { role: required.role, actionType: safeEvent.actionType });
    if (safeEvent.role !== request.role) fail("ROLE_DENIED");
    if (safeEvent.signingDigest !== request.signingDigest) fail("SIGNATURE_INVALID");
    const submittedActionDigests = [...aggregate.submittedActionDigests, safeEvent.signingDigest];
    const state = safeEvent.actionType === "PROPOSAL" ? "PROPOSAL_PENDING" : "ACCEPTANCE_PENDING";
    const provisional = advanceAggregate(aggregate, {
      state,
      submittedActionDigests,
      eventCursor: safeEvent.eventCursor ?? aggregate.eventCursor,
      pendingSigningRequest: undefined,
    });
    return normalizeAggregate({
      ...provisional,
      pendingSigningRequest: plannedSigningRequest(
        provisional,
        safeEvent.actionType === "PROPOSAL" ? "ACCEPTANCE" : "EVIDENCE",
        "RESPONDER",
      ),
    });
  }
  if (safeEvent.type === "CHECKPOINT_SUBMITTED") {
    if (safeEvent.role !== "RESPONDER") fail("ROLE_DENIED");
    assertDigest(safeEvent.signingDigest);
    assertEventState(aggregate, ["ACCEPTANCE_PENDING"]);
    const request = assertPendingRequest(aggregate, { role: "RESPONDER", actionType: "EVIDENCE" });
    if (safeEvent.signingDigest !== request.signingDigest) fail("SIGNATURE_INVALID");
    return advanceAggregate(aggregate, {
      state: "ANCHORING",
      submittedActionDigests: [...aggregate.submittedActionDigests, safeEvent.signingDigest],
      eventCursor: safeEvent.eventCursor ?? aggregate.eventCursor,
      pendingSigningRequest: undefined,
    });
  }
  if (safeEvent.type === "CLOCKCHAIN_CERTIFICATE_ISSUED") {
    assertEventState(aggregate, ["ANCHORING"]);
    assertDigest(safeEvent.certificateDigest);
    return advanceAggregate(aggregate, {
      state: "CERTIFICATE_ISSUED",
      certificateDigest: safeEvent.certificateDigest ?? aggregate.certificateDigest,
      eventCursor: safeEvent.eventCursor ?? aggregate.eventCursor,
    });
  }
  if (safeEvent.type === "CLOCKCHAIN_CONTINUATION_ISSUED") {
    assertEventState(aggregate, ["CERTIFICATE_ISSUED"]);
    assertDigest(safeEvent.certificateDigest);
    assertDigest(safeEvent.continuationDigest);
    if (aggregate.certificateDigest && safeEvent.certificateDigest !== aggregate.certificateDigest) fail("CLOCKCHAIN_RECEIPT_INVALID");
    return advanceAggregate(aggregate, {
      state: "CONTINUATION_ISSUED",
      certificateDigest: safeEvent.certificateDigest ?? aggregate.certificateDigest,
      continuationDigest: safeEvent.continuationDigest,
      eventCursor: safeEvent.eventCursor ?? aggregate.eventCursor,
    });
  }
  fail("SCHEMA_INVALID");
}

function submissionNow(wrapper, aggregate) {
  return wrapper.now ?? aggregate.updatedAt ?? aggregate.createdAt ?? aggregate.expiresAt;
}

function assertExpectedPartyBinding(aggregate, expectedParty, role) {
  const party = validateHandshakeV3Party(expectedParty);
  if (party.role !== role) fail("ROLE_DENIED");
  if (!aggregate.joinedPartyDigests[role] || party.identityDigest !== aggregate.joinedPartyDigests[role]) {
    fail("PRINCIPAL_DENIED");
  }
  return party;
}

export async function validateHandshakeV3ActionSubmission(aggregateInput, input) {
  const aggregate = normalizeAggregate(aggregateInput);
  const wrapper = snapshotTopLevelRecord(input, SUBMISSION_WRAPPER_KEYS);
  const { input: toolInput } = validateHandshakeV3ToolInput("agent_handshake_session_submit", wrapper.toolInput);
  if (toolInput.sessionId !== aggregate.sessionId) fail("TRANSITION_DENIED");
  assertExpectedStateVersion(aggregate, toolInput.expectedStateVersion);
  const request = aggregate.pendingSigningRequest;
  if (!request) fail("TRANSITION_DENIED");
  if (request.actionType !== "PROPOSAL" && request.actionType !== "ACCEPTANCE") fail("TRANSITION_DENIED");
  const expectedState = request.actionType === "PROPOSAL" ? "PARTIES_BOUND" : "PROPOSAL_PENDING";
  assertEventState(aggregate, [expectedState]);
  const expectedParty = assertExpectedPartyBinding(aggregate, wrapper.expectedParty, request.role);
  await verifyHandshakeV3SignedAction({
    request,
    action: toolInput.action,
    expectedParty,
    expectedRole: request.role,
    expectedSigningRequestId: request.signingRequestId,
    expectedSigningDigest: request.signingDigest,
    now: submissionNow(wrapper, aggregate),
    verifier: wrapper.verifier,
  });
  return Object.freeze({
    type: "ACTION_SUBMITTED",
    expectedStateVersion: aggregate.stateVersion,
    role: request.role,
    actionType: request.actionType,
    signingDigest: request.signingDigest,
    eventCursor: wrapper.eventCursor ?? aggregate.eventCursor,
  });
}

export async function validateHandshakeV3CheckpointSubmission(aggregateInput, input) {
  const aggregate = normalizeAggregate(aggregateInput);
  const wrapper = snapshotTopLevelRecord(input, SUBMISSION_WRAPPER_KEYS);
  const { input: toolInput } = validateHandshakeV3ToolInput("agent_handshake_session_submit_checkpoint", wrapper.toolInput);
  if (toolInput.sessionId !== aggregate.sessionId) fail("TRANSITION_DENIED");
  assertExpectedStateVersion(aggregate, toolInput.expectedStateVersion);
  const request = aggregate.pendingSigningRequest;
  if (!request) fail("TRANSITION_DENIED");
  if (request.actionType !== "EVIDENCE" || request.role !== "RESPONDER") fail("ROLE_DENIED");
  assertEventState(aggregate, ["ACCEPTANCE_PENDING"]);
  if (toolInput.checkpointType !== "ACCEPTED") fail("TRANSITION_DENIED");
  const expectedParty = assertExpectedPartyBinding(aggregate, wrapper.expectedParty, request.role);
  await verifyHandshakeV3SignedAction({
    request,
    action: {
      signingRequestId: toolInput.signingRequestId,
      signingDigest: toolInput.signingDigest,
      signerKeyId: toolInput.signerKeyId,
      algorithm: toolInput.algorithm,
      signature: toolInput.signature,
    },
    expectedParty,
    expectedRole: request.role,
    expectedSigningRequestId: request.signingRequestId,
    expectedSigningDigest: request.signingDigest,
    now: submissionNow(wrapper, aggregate),
    verifier: wrapper.verifier,
  });
  return Object.freeze({
    type: "CHECKPOINT_SUBMITTED",
    expectedStateVersion: aggregate.stateVersion,
    role: request.role,
    signingDigest: request.signingDigest,
    eventCursor: wrapper.eventCursor ?? aggregate.eventCursor,
  });
}
