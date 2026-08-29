import { HANDSHAKE_V3_NONTERMINAL_STATES, HANDSHAKE_V3_TERMINAL_STATES, fail } from "./constants.mjs";

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
  FAIL_CLOSED: ["SYSTEM", "FAILED_CLOSED"],
  CANCEL: ["INITIATOR", "CANCELLED"],
  EXPIRE: ["CLOCKCHAIN", "EXPIRED"],
  REVOKE: ["CLOCKCHAIN", "REVOKED"],
});

function denied(session, code) {
  return Object.freeze({ allowed: false, error: Object.freeze({ code }), session });
}

function advanced(session, state) {
  return Object.freeze({
    allowed: true,
    session: Object.freeze({
      ...session,
      state,
      stateVersion: session.stateVersion + 1,
      signedObjects: session.signedObjects,
    }),
  });
}

export function applyHandshakeV3Transition(session, transition) {
  if (transition.expectedStateVersion !== session.stateVersion) {
    return denied(session, "STATE_VERSION_CONFLICT");
  }
  if (session.state === "COMPLETED") {
    if (transition.actionType === "REVOKE" && transition.actor === "CLOCKCHAIN") {
      return advanced(session, "REVOKED");
    }
    return denied(session, "STATE_TRANSITION_DENIED");
  }
  if (HANDSHAKE_V3_TERMINAL_STATES.includes(session.state)) {
    return denied(session, "STATE_TRANSITION_DENIED");
  }
  if (TERMINAL_ACTIONS[transition.actionType]) {
    const [actor, nextState] = TERMINAL_ACTIONS[transition.actionType];
    if (transition.actor !== actor) {
      return denied(session, "AUTHORITY_DENIED");
    }
    return advanced(session, nextState);
  }
  const allowed = HAPPY_PATH[session.state]?.[transition.actionType];
  if (!allowed) {
    return denied(session, "STATE_TRANSITION_DENIED");
  }
  const [actor, nextState] = allowed;
  if (transition.actor !== actor) {
    return denied(session, "AUTHORITY_DENIED");
  }
  return advanced(session, nextState);
}

export function evaluateHandshakeV3OperatorRequest(session, request) {
  if (!["REQUEST_EXPIRY_EVALUATION", "REQUEST_CANCELLATION"].includes(request.action)) {
    fail("SCHEMA_INVALID");
  }
  if (request.observedStateVersion !== session.stateVersion) {
    fail("STATE_VERSION_CONFLICT");
  }
  return Object.freeze({
    acceptedForEvaluation: true,
    mutated: false,
    allowedActions: Object.freeze(request.action === "REQUEST_EXPIRY_EVALUATION" ? ["EXPIRE"] : ["CANCEL"]),
    nonterminal: HANDSHAKE_V3_NONTERMINAL_STATES.includes(session.state),
    session,
  });
}
