import assert from "node:assert/strict";
import test from "node:test";

import {
  HANDSHAKE_V3_NONTERMINAL_STATES,
  HANDSHAKE_V3_TERMINAL_STATES,
  applyHandshakeV3Transition,
  evaluateHandshakeV3OperatorRequest,
} from "@clockchain/handshake-protocol/v3";

test("v3 lifecycle permits the approved happy-path sequence with CAS state versions", () => {
  let session = { sessionId: "sess_a", state: "INVITED", stateVersion: 0, signedObjects: Object.freeze([]) };
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
    const next = applyHandshakeV3Transition(session, { actionType, actor, expectedStateVersion: session.stateVersion });
    assert.equal(next.allowed, true, actionType);
    assert.equal(next.session.state, nextState);
    assert.equal(next.session.stateVersion, session.stateVersion + 1);
    assert.notEqual(next.session, session);
    session = next.session;
  }
});

test("v3 lifecycle denies stale, forbidden, and unauthorized transitions without mutation", () => {
  const session = Object.freeze({ sessionId: "sess_a", state: "PARTIES_BOUND", stateVersion: 3, signedObjects: Object.freeze(["signed-proposal"]) });

  for (const denied of [
    { actionType: "SUBMIT_ACCEPTANCE", actor: "RESPONDER", expectedStateVersion: 3, code: "STATE_TRANSITION_DENIED" },
    { actionType: "SUBMIT_PROPOSAL", actor: "OPERATOR", expectedStateVersion: 3, code: "AUTHORITY_DENIED" },
    { actionType: "SUBMIT_PROPOSAL", actor: "INITIATOR", expectedStateVersion: 2, code: "STATE_VERSION_CONFLICT" },
  ]) {
    const result = applyHandshakeV3Transition(session, denied);
    assert.equal(result.allowed, false, denied.actionType);
    assert.equal(result.error.code, denied.code);
    assert.equal(result.session, session);
  }
});

test("nonterminal states may fail closed, cancel, expire, or revoke; completed can only revoke without mutating signed objects", () => {
  for (const state of HANDSHAKE_V3_NONTERMINAL_STATES) {
    for (const [actionType, actor, expected] of [
      ["FAIL_CLOSED", "SYSTEM", "FAILED_CLOSED"],
      ["CANCEL", "INITIATOR", "CANCELLED"],
      ["EXPIRE", "CLOCKCHAIN", "EXPIRED"],
      ["REVOKE", "CLOCKCHAIN", "REVOKED"],
    ]) {
      const session = { sessionId: `sess_${state}`, state, stateVersion: 1, signedObjects: Object.freeze(["immutable"]) };
      const result = applyHandshakeV3Transition(session, { actionType, actor, expectedStateVersion: 1 });
      assert.equal(result.allowed, true, `${state}:${actionType}`);
      assert.equal(result.session.state, expected);
      assert.equal(result.session.signedObjects, session.signedObjects);
    }
  }

  assert.deepEqual(HANDSHAKE_V3_TERMINAL_STATES, ["COMPLETED", "FAILED_CLOSED", "CANCELLED", "EXPIRED", "REVOKED"]);
  const completed = Object.freeze({ sessionId: "sess_done", state: "COMPLETED", stateVersion: 9, signedObjects: Object.freeze(["cert", "cont"]) });
  assert.equal(applyHandshakeV3Transition(completed, { actionType: "COMPLETE", actor: "CLOCKCHAIN", expectedStateVersion: 9 }).allowed, false);
  const revoked = applyHandshakeV3Transition(completed, { actionType: "REVOKE", actor: "CLOCKCHAIN", expectedStateVersion: 9 });
  assert.equal(revoked.allowed, true);
  assert.equal(revoked.session.state, "REVOKED");
  assert.equal(revoked.session.signedObjects, completed.signedObjects);
});

test("operator and Supervisor lifecycle requests are request-only evaluations", () => {
  const session = Object.freeze({ sessionId: "sess_a", state: "PROPOSAL_PENDING", stateVersion: 5, signedObjects: Object.freeze([]) });
  const request = evaluateHandshakeV3OperatorRequest(session, {
    action: "REQUEST_EXPIRY_EVALUATION",
    observedStateVersion: 5,
    reasonCode: "DEADLINE_REACHED",
  });
  assert.equal(request.acceptedForEvaluation, true);
  assert.equal(request.mutated, false);
  assert.equal(request.session, session);

  assert.throws(() => evaluateHandshakeV3OperatorRequest(session, { action: "RECOVER_AGENT_ROLE", observedStateVersion: 5, reasonCode: "OTHER" }), { code: "SCHEMA_INVALID" });
  assert.equal(applyHandshakeV3Transition(session, { actionType: "EXPIRE", actor: "OPERATOR", expectedStateVersion: 5 }).allowed, false);
});
