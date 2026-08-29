import { HANDSHAKE_V3_NONTERMINAL_STATES, HANDSHAKE_V3_TERMINAL_STATES, fail } from "./constants.mjs";
import { validateHandshakeV3Session } from "./validators.mjs";

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
  const happy = Object.keys(HAPPY_PATH[state] ?? {});
  const terminal = HANDSHAKE_V3_NONTERMINAL_STATES.includes(state)
    ? Object.keys(TERMINAL_ACTIONS)
    : state === "COMPLETED"
      ? ["REVOKE"]
      : [];
  return [...new Set([...happy, ...terminal])];
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
