import {
  HANDSHAKE_V3_ALLOWED_TRANSITIONS_BY_STATE,
  HANDSHAKE_V3_NONTERMINAL_STATES,
  HANDSHAKE_V3_SCHEMA_VERSION,
  HANDSHAKE_V3_TERMINAL_STATES,
  fail,
} from "./constants.mjs";
import { handshakeV3Digest } from "./canonical.mjs";
import { createHandshakeV3SigningRequest } from "./signing.mjs";
import { validateHandshakeV3Session, validateHandshakeV3ToolResult } from "./validators.mjs";

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
  aggregate.eventCursor ??= "cursor.initial";
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

function waitPlan(aggregate, role, waitingOn, requiredTool = "agent_handshake_session_next", changed = false) {
  return validateHandshakeV3ToolResult("agent_handshake_session_next", {
    changed,
    nextAction: "WAIT",
    session: projectHandshakeV3SessionForRole(aggregate, role),
    events: [],
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
  return waitPlan(aggregate, role, waitingOn, waitingOn === "CLOCKCHAIN" ? "agent_handshake_session_get_result" : "agent_handshake_session_next", options.changed === true);
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

export function applyHandshakeV3ToolEvent(aggregateInput, event) {
  const aggregate = normalizeAggregate(aggregateInput);
  if (!event?.type) fail("SCHEMA_INVALID");
  if (event.type === "INVITATION_ACCEPTED") {
    return advanceAggregate(aggregate, { state: "CLAIMED", eventCursor: event.eventCursor ?? aggregate.eventCursor });
  }
  if (event.type === "SESSION_JOINED") {
    if (!["INITIATOR", "RESPONDER"].includes(event.role) || !event.partyDigest) fail("SCHEMA_INVALID");
    const joinedPartyDigests = { ...aggregate.joinedPartyDigests, [event.role]: event.partyDigest };
    if (joinedPartyDigests.INITIATOR && joinedPartyDigests.RESPONDER) {
      const provisional = advanceAggregate(aggregate, {
        state: "PARTIES_BOUND",
        joinedPartyDigests,
        eventCursor: event.eventCursor ?? aggregate.eventCursor,
      });
      return normalizeAggregate({
        ...provisional,
        pendingSigningRequest: plannedSigningRequest(provisional, "PROPOSAL", "INITIATOR"),
      });
    }
    return advanceAggregate(aggregate, { joinedPartyDigests, eventCursor: event.eventCursor ?? aggregate.eventCursor });
  }
  if (event.type === "ACTION_SUBMITTED") {
    const submittedActionDigests = [...aggregate.submittedActionDigests, event.signingDigest];
    const state = event.actionType === "PROPOSAL" ? "PROPOSAL_PENDING" : "ACCEPTANCE_PENDING";
    const provisional = advanceAggregate(aggregate, {
      state,
      submittedActionDigests,
      eventCursor: event.eventCursor ?? aggregate.eventCursor,
      pendingSigningRequest: undefined,
    });
    return normalizeAggregate({
      ...provisional,
      pendingSigningRequest: plannedSigningRequest(
        provisional,
        event.actionType === "PROPOSAL" ? "ACCEPTANCE" : "EVIDENCE",
        "RESPONDER",
      ),
    });
  }
  if (event.type === "CHECKPOINT_SUBMITTED") {
    return advanceAggregate(aggregate, {
      state: "ANCHORING",
      submittedActionDigests: [...aggregate.submittedActionDigests, event.signingDigest],
      eventCursor: event.eventCursor ?? aggregate.eventCursor,
      pendingSigningRequest: undefined,
    });
  }
  if (event.type === "CLOCKCHAIN_CERTIFICATE_ISSUED") {
    return advanceAggregate(aggregate, {
      state: "CERTIFICATE_ISSUED",
      certificateDigest: event.certificateDigest ?? aggregate.certificateDigest,
      eventCursor: event.eventCursor ?? aggregate.eventCursor,
    });
  }
  if (event.type === "CLOCKCHAIN_CONTINUATION_ISSUED") {
    return advanceAggregate(aggregate, {
      state: "CONTINUATION_ISSUED",
      certificateDigest: event.certificateDigest ?? aggregate.certificateDigest,
      continuationDigest: event.continuationDigest,
      eventCursor: event.eventCursor ?? aggregate.eventCursor,
    });
  }
  fail("SCHEMA_INVALID");
}

export function validateHandshakeV3ActionSubmission(aggregateInput, input) {
  const aggregate = normalizeAggregate(aggregateInput);
  const request = aggregate.pendingSigningRequest;
  if (!request || !input?.action || input.role !== request.role) fail("ROLE_DENIED");
  if (request.actionType !== "PROPOSAL" && request.actionType !== "ACCEPTANCE") fail("TRANSITION_DENIED");
  if (
    input.action.signingRequestId !== request.signingRequestId ||
    input.action.signingDigest !== request.signingDigest
  ) fail("SIGNATURE_INVALID");
  return Object.freeze({
    type: "ACTION_SUBMITTED",
    role: input.role,
    actionType: request.actionType,
    signingDigest: request.signingDigest,
    eventCursor: input.eventCursor ?? aggregate.eventCursor,
  });
}

export function validateHandshakeV3CheckpointSubmission(aggregateInput, input) {
  const aggregate = normalizeAggregate(aggregateInput);
  const request = aggregate.pendingSigningRequest;
  if (!request || request.actionType !== "EVIDENCE" || input?.role !== request.role) fail("ROLE_DENIED");
  if (input.checkpointType !== "ACCEPTED") fail("TRANSITION_DENIED");
  if (input.signingRequestId !== request.signingRequestId || input.signingDigest !== request.signingDigest) fail("SIGNATURE_INVALID");
  return Object.freeze({
    type: "CHECKPOINT_SUBMITTED",
    role: input.role,
    signingDigest: request.signingDigest,
    eventCursor: input.eventCursor ?? aggregate.eventCursor,
  });
}
