import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  HANDSHAKE_V3_ALLOWED_TRANSITIONS_BY_STATE,
  HANDSHAKE_V3_CONTRACT_SCHEMA,
  HANDSHAKE_V3_ERROR_CODES,
  HANDSHAKE_V3_INITIATOR_REQUIRED_TOOLS,
  HANDSHAKE_V3_NEXT_ACTIONS,
  HANDSHAKE_V3_NEXT_ACTION_BY_STATE,
  HANDSHAKE_V3_RESPONDER_REQUIRED_TOOLS,
  HANDSHAKE_V3_SIGNING_ALGORITHMS,
  HANDSHAKE_V3_TOOL_NAMES,
  validateHandshakeV3Def,
  validateHandshakeV3ResponseEnvelope,
  validateHandshakeV3Schema,
  validateHandshakeV3ToolInput,
  validateHandshakeV3ToolResult,
} from "@clockchain/handshake-protocol/v3";

const schema = JSON.parse(
  await readFile(new URL("../schemas/standalone-handshake-v3-contract.schema.json", import.meta.url), "utf8"),
);

const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const digestC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const opaque = "opaque_identifier_123";
const later = "2026-08-29T21:00:00Z";

function roleGrantSample() {
  return sampleForSchema(schema.$defs.roleGrant);
}

function policySample() {
  return sampleForSchema(schema.$defs.policy);
}

function partySample(role = "INITIATOR", identityDigest = digest) {
  return {
    ...sampleForSchema(schema.$defs.party),
    role,
    identityDigest,
  };
}

function sessionSample() {
  return sampleForSchema(schema.$defs.session);
}

function tenantRelationSample(relationType = "INITIATOR_CREATED") {
  return {
    relationType,
    localTenantDigest: digest,
    counterpartyTenantDigest: digestB,
    binding: "FIRST_AUTHENTICATED_CLAIM",
    visibility: relationType === "INITIATOR_CREATED" ? "CREATOR_VIEW" : "RESPONDER_VIEW",
    federationSubjectDigest: digestC,
  };
}

function signingRequestSample(actionType = "PROPOSAL", role = "INITIATOR", stateVersion = 4) {
  return {
    ...sampleForSchema(schema.$defs.signingRequest),
    actionType,
    role,
    stateVersion,
  };
}

function sessionFor({
  sessionId = "sess_semantic_012345",
  role = "INITIATOR",
  state = "INVITED",
  policy = policySample(),
  policyDigest = digest,
  expiresAt = later,
  allowedTransitions = HANDSHAKE_V3_ALLOWED_TRANSITIONS_BY_STATE[state],
  pendingSigningRequest,
} = {}) {
  return {
    ...sessionSample(),
    sessionId,
    role,
    state,
    stateVersion: state === "INVITED" ? 0 : 1,
    policy,
    policyDigest,
    expiresAt,
    allowedTransitions: [...allowedTransitions],
    ...(pendingSigningRequest ? { pendingSigningRequest } : {}),
  };
}

function grantFor({
  role = "INITIATOR",
  sessionId = "sess_semantic_012345",
  allowedTools = role === "INITIATOR" ? HANDSHAKE_V3_INITIATOR_REQUIRED_TOOLS : HANDSHAKE_V3_RESPONDER_REQUIRED_TOOLS,
} = {}) {
  return {
    ...roleGrantSample(),
    sessionId,
    role,
    allowedTools: [...allowedTools],
  };
}

function invitationCreateResult(overrides = {}) {
  const sessionId = overrides.sessionId ?? "sess_semantic_012345";
  const policy = overrides.policy ?? policySample();
  const policyDigest = overrides.policyDigest ?? digest;
  return {
    invitationId: "inv_semantic_012345",
    invitationToken: "tok_semantic_012345",
    sessionId,
    roleGrant: grantFor({ role: "INITIATOR", sessionId }),
    tenantRelation: tenantRelationSample("INITIATOR_CREATED"),
    session: sessionFor({ sessionId, role: "INITIATOR", state: "INVITED", policy, policyDigest }),
    policyDigest,
    statementDigest: digestB,
    state: "ISSUED",
    expiresAt: later,
    ...overrides,
  };
}

function invitationAcceptResult(overrides = {}) {
  const sessionId = overrides.sessionId ?? "sess_semantic_012345";
  const policy = overrides.policy ?? policySample();
  const policyDigest = overrides.policyDigest ?? digest;
  return {
    sessionId,
    roleGrant: grantFor({ role: "RESPONDER", sessionId }),
    tenantRelation: tenantRelationSample("RESPONDER_ACCEPTED"),
    session: sessionFor({ sessionId, role: "RESPONDER", state: "CLAIMED", policy, policyDigest }),
    ...overrides,
  };
}

function nextResult({ state, nextAction, pendingSigningRequest, retryAfterMs, allowedTransitions } = {}) {
  const sessionId = "sess_semantic_012345";
  const role = pendingSigningRequest?.role ?? "INITIATOR";
  const stateVersion = state === "INVITED" ? 0 : 1;
  const policyDigest = digest;
  return {
    changed: nextAction !== "WAIT",
    nextAction,
    session: sessionFor({
      sessionId,
      role,
      state,
      policyDigest,
      allowedTransitions,
      pendingSigningRequest: pendingSigningRequest
        ? { ...pendingSigningRequest, sessionId, role, stateVersion, policyDigest }
        : undefined,
    }),
    events: [],
    retryAfterMs,
  };
}

function sampleForSchema(fragment) {
  if (!fragment) return opaque;
  if (fragment.$ref) {
    if (fragment.$ref === "#/errorCodes") return "SCHEMA_INVALID";
    return sampleForSchema(schema.$defs[fragment.$ref.slice("#/$defs/".length)]);
  }
  if (fragment.const !== undefined) return fragment.const;
  if (fragment.enum) return fragment.enum[0];
  if (fragment.oneOf) {
    return { ...sampleForSchema({ type: "object", properties: fragment.properties, required: fragment.required, additionalProperties: fragment.additionalProperties }), ...sampleForSchema(fragment.oneOf[0]) };
  }
  if (fragment.type === "string" || fragment.format) {
    if (fragment.format === "uuid") return "01234567-89ab-4def-8123-456789abcdef";
    if (fragment.format === "date-time") return later;
    if (fragment.pattern?.includes("sha256")) return digest;
    if (fragment.pattern?.includes("agent_handshake_")) return "agent_handshake_session_next";
    if (fragment.pattern) return "opaque_value_12345";
    return "x".repeat(Math.max(fragment.minLength ?? 1, 16));
  }
  if (fragment.type === "integer") return Math.max(fragment.minimum ?? 0, 1);
  if (fragment.type === "number") return 1;
  if (fragment.type === "boolean") return true;
  if (Array.isArray(fragment.type)) {
    if (fragment.type.includes("string")) return "value";
    if (fragment.type.includes("number")) return 1;
    if (fragment.type.includes("boolean")) return true;
    if (fragment.type.includes("null")) return null;
  }
  if (fragment.type === "array") {
    const min = fragment.minItems ?? 1;
    return Array.from({ length: min }, (_, index) => {
      const value = sampleForSchema(fragment.items ?? {});
      return fragment.uniqueItems && typeof value === "string" && !fragment.items?.$ref && !fragment.items?.enum
        ? `${value}_${index}`
        : value;
    });
  }
  if (fragment.type === "object" || fragment.properties || fragment.required) {
    const output = {};
    for (const key of fragment.required ?? []) {
      output[key] = sampleForSchema(fragment.properties?.[key]);
    }
    return output;
  }
  return {};
}

function responseEnvelope(result) {
  return {
    protocolVersion: "3.0",
    schemaVersion: "3.0.0-draft.2",
    requestId: "01234567-89ab-4def-8123-456789abcdef",
    serverTime: later,
    result,
    receipt: sampleForSchema(schema.$defs.receipt),
  };
}

function assertGenericObjectSurfacesReject(value) {
  assert.throws(() => validateHandshakeV3ResponseEnvelope(responseEnvelope(value)), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_capabilities", {
    negotiatedProtocolVersion: "3.0",
    schemaVersion: "3.0.0-draft.2",
    toolsetDigest: digest,
    trustRootIds: ["root-2026-08"],
    limits: value,
  }), { code: "SCHEMA_INVALID" });
}

test("constants mirror the normative schema enums exactly", () => {
  assert.deepEqual(HANDSHAKE_V3_CONTRACT_SCHEMA.errorCodes.enum, schema.errorCodes.enum);
  assert.deepEqual(HANDSHAKE_V3_ERROR_CODES, schema.errorCodes.enum);
  assert.deepEqual(HANDSHAKE_V3_SIGNING_ALGORITHMS, ["ES256K", "EdDSA", "ES256"]);
  assert.deepEqual(HANDSHAKE_V3_NEXT_ACTIONS, [
    "WAIT",
    "SIGN_AND_SUBMIT",
    "SUBMIT_CHECKPOINT",
    "FETCH_RESULT",
    "STOP_AFTER_VERIFICATION",
    "TERMINAL",
  ]);
  assert.deepEqual(HANDSHAKE_V3_INITIATOR_REQUIRED_TOOLS, [
    "agent_handshake_session_join",
    "agent_handshake_session_next",
    "agent_handshake_session_submit_checkpoint",
    "agent_handshake_session_submit",
    "agent_handshake_session_cancel",
    "agent_handshake_session_resume",
  ]);
  assert.deepEqual(HANDSHAKE_V3_RESPONDER_REQUIRED_TOOLS, HANDSHAKE_V3_INITIATOR_REQUIRED_TOOLS);
  assert.deepEqual(HANDSHAKE_V3_ALLOWED_TRANSITIONS_BY_STATE, {
    INVITED: ["CLAIM_INVITATION", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"],
    CLAIMED: ["PREPARE_POLICY", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"],
    POLICY_READY: ["BIND_PARTIES", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"],
    PARTIES_BOUND: ["SUBMIT_PROPOSAL", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"],
    PROPOSAL_PENDING: ["SUBMIT_ACCEPTANCE", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"],
    ACCEPTANCE_PENDING: ["CONFIRM_ANCHOR", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"],
    ANCHORING: ["ISSUE_CERTIFICATE", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"],
    CERTIFICATE_ISSUED: ["ISSUE_CONTINUATION", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"],
    CONTINUATION_ISSUED: ["COMPLETE", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"],
    COMPLETED: ["REVOKE"],
    FAILED_CLOSED: [],
    CANCELLED: [],
    EXPIRED: [],
    REVOKED: [],
  });
  assert.equal(HANDSHAKE_V3_NEXT_ACTION_BY_STATE.PROPOSAL_PENDING, "SIGN_AND_SUBMIT");
  assert.equal(HANDSHAKE_V3_NEXT_ACTION_BY_STATE.CERTIFICATE_ISSUED, "FETCH_RESULT");
  assert.deepEqual(HANDSHAKE_V3_TOOL_NAMES, schema.tools.map((tool) => tool.name));
  assert.equal(HANDSHAKE_V3_TOOL_NAMES.length, 16);
  assert.equal(HANDSHAKE_V3_TOOL_NAMES.includes("agent_handshake_session_verify"), false);
});

test("draft.2 schema is explicit and draft.1 envelopes are not accepted", () => {
  assert.equal(schema.protocolVersion, "3.0");
  assert.equal(schema.schemaVersion, "3.0.0-draft.2");
  assert.equal(HANDSHAKE_V3_CONTRACT_SCHEMA.schemaVersion, "3.0.0-draft.2");

  assert.throws(() => validateHandshakeV3ResponseEnvelope({
    ...responseEnvelope({ ok: true }),
    schemaVersion: "3.0.0-draft.1",
  }), { code: "SCHEMA_INVALID" });
});

test("exported contract schema is deeply immutable and cannot weaken validators", () => {
  const policyScopeSchema = HANDSHAKE_V3_CONTRACT_SCHEMA.$defs.policy.properties.scope;
  const resultVerifySchema = HANDSHAKE_V3_CONTRACT_SCHEMA.tools.find(
    (tool) => tool.name === "agent_handshake_result_verify",
  ).inputSchema;

  assert.equal(Object.isFrozen(HANDSHAKE_V3_CONTRACT_SCHEMA.$defs), true);
  assert.equal(Object.isFrozen(policyScopeSchema), true);
  assert.equal(Object.isFrozen(resultVerifySchema.required), true);
  assert.throws(() => {
    policyScopeSchema.minItems = 0;
  }, TypeError);
  assert.throws(() => {
    resultVerifySchema.required.length = 0;
  }, TypeError);

  assert.throws(() => validateHandshakeV3Def("policy", {
    scope: [],
    constraints: {},
    externalBusinessActionsAllowed: false,
    expiresAt: later,
  }), { code: "SCHEMA_INVALID" });
  assert.throws(
    () => validateHandshakeV3ToolInput("agent_handshake_result_verify", {}),
    { code: "SCHEMA_INVALID" },
  );
});

test("generic object schema surfaces recursively clone only safe JSON", () => {
  const nested = {
    tenant: {
      labels: ["external", "isolated"],
      limits: { sessions: 2, burst: null, enabled: true },
    },
  };
  assert.deepEqual(validateHandshakeV3ResponseEnvelope(responseEnvelope(nested)).result, nested);
  assert.deepEqual(validateHandshakeV3ToolResult("agent_handshake_capabilities", {
    negotiatedProtocolVersion: "3.0",
    schemaVersion: "3.0.0-draft.2",
    toolsetDigest: digest,
    trustRootIds: ["root-2026-08"],
    limits: nested,
  }).limits, nested);

  assertGenericObjectSurfacesReject({ nested: { businessContent: "smuggled" } });
  assertGenericObjectSurfacesReject({ nested: { payload: { action: "AUTHOR_BUSINESS_CONTENT" } } });

  const nestedAccessor = { nested: {} };
  Object.defineProperty(nestedAccessor.nested, "safe", {
    enumerable: true,
    get() {
      throw new Error("raw accessor must not escape");
    },
  });
  assertGenericObjectSurfacesReject(nestedAccessor);

  assertGenericObjectSurfacesReject({ nested: new Proxy({}, {
    getPrototypeOf() {
      throw new Error("raw getPrototypeOf trap must not escape");
    },
  }) });
  assertGenericObjectSurfacesReject({ nested: new Proxy({}, {
    ownKeys() {
      throw new Error("raw ownKeys trap must not escape");
    },
  }) });
  assertGenericObjectSurfacesReject({ nested: new Proxy({ value: true }, {
    getOwnPropertyDescriptor() {
      throw new Error("raw descriptor trap must not escape");
    },
  }) });

  assertGenericObjectSurfacesReject({ nested: { [Symbol("hidden")]: true } });
  assertGenericObjectSurfacesReject({ nested: new Date("2026-08-29T20:00:00Z") });
  assertGenericObjectSurfacesReject({ nested: { unsupported: undefined } });
  assertGenericObjectSurfacesReject({ nested: { unsupported: () => true } });
  assertGenericObjectSurfacesReject({ nested: { unsupported: 1n } });
  assertGenericObjectSurfacesReject({ nested: { unsupported: Number.NaN } });

  const cyclic = {};
  cyclic.self = cyclic;
  assertGenericObjectSurfacesReject({ nested: cyclic });
});

test("schema engine validates every $defs object and rejects alternate public shapes", () => {
  for (const defName of Object.keys(schema.$defs)) {
    const sample = sampleForSchema(schema.$defs[defName]);
    assert.deepEqual(validateHandshakeV3Def(defName, sample), sample, defName);
    if (schema.$defs[defName].type === "object") {
      assert.throws(() => validateHandshakeV3Def(defName, { ...sample, extra: true }), { code: "SCHEMA_INVALID" }, `${defName} extra`);
      assert.throws(() => validateHandshakeV3Def(defName, { ...sample, businessContent: "forbidden" }), { code: "SCHEMA_INVALID" }, `${defName} business`);
    }
  }

  assert.throws(() => validateHandshakeV3Def("roleGrant", {
    roleGrantId: opaque,
    sessionId: opaque,
    role: "INITIATOR",
    principalDigest: digest,
    proofKeyThumbprint: digestB,
    allowedTools: ["agent_handshake_session_next"],
    issuedAt: "2026-08-29T20:00:00Z",
    expiresAt: later,
  }), { code: "SCHEMA_INVALID" });

  assert.throws(() => validateHandshakeV3Def("session", {
    sessionId: opaque,
    role: "INITIATOR",
    state: "INVITED",
    stateVersion: 0,
    tenantDigest: digest,
    createdAt: "2026-08-29T20:00:00Z",
    expiresAt: later,
    signedObjects: [],
  }), { code: "SCHEMA_INVALID" });
});

test("invitation create returns the creator role grant and creator-view invited session", () => {
  const result = validateHandshakeV3ToolResult("agent_handshake_invitation_create", invitationCreateResult());

  assert.equal(result.sessionId, result.roleGrant.sessionId);
  assert.equal(result.roleGrant.role, "INITIATOR");
  assert.equal(result.session.role, "INITIATOR");
  assert.equal(result.session.state, "INVITED");
});

test("invitation create rejects swapped roles and inconsistent creator bindings", () => {
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_create", {
    ...invitationCreateResult(),
    roleGrant: grantFor({ role: "RESPONDER" }),
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_create", {
    ...invitationCreateResult(),
    session: sessionFor({ role: "RESPONDER", state: "INVITED" }),
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_create", {
    ...invitationCreateResult(),
    sessionId: "sess_other_012345",
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_create", {
    ...invitationCreateResult(),
    policyDigest: digestB,
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_create", {
    ...invitationCreateResult(),
    expiresAt: "2026-08-29T22:00:00Z",
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_create", {
    ...invitationCreateResult(),
    session: sessionFor({ role: "INITIATOR", state: "CLAIMED" }),
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_create", {
    ...invitationCreateResult(),
    roleGrant: grantFor({ role: "INITIATOR", allowedTools: ["agent_handshake_session_next"] }),
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_create", {
    ...invitationCreateResult(),
    roleGrant: grantFor({
      role: "INITIATOR",
      allowedTools: [...HANDSHAKE_V3_INITIATOR_REQUIRED_TOOLS, "agent_handshake_operator_request"],
    }),
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_create", {
    ...invitationCreateResult(),
    session: sessionFor({
      role: "INITIATOR",
      state: "INVITED",
      allowedTransitions: [...HANDSHAKE_V3_ALLOWED_TRANSITIONS_BY_STATE.INVITED, "PREPARE_POLICY"],
    }),
  }), { code: "SCHEMA_INVALID" });
});

test("invitation accept rejects swapped roles and inconsistent responder bindings", () => {
  assert.equal(validateHandshakeV3ToolResult("agent_handshake_invitation_accept", invitationAcceptResult()).roleGrant.role, "RESPONDER");
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_accept", {
    ...invitationAcceptResult(),
    roleGrant: grantFor({ role: "INITIATOR" }),
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_accept", {
    ...invitationAcceptResult(),
    session: sessionFor({ role: "INITIATOR", state: "CLAIMED" }),
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_accept", {
    ...invitationAcceptResult(),
    session: sessionFor({ role: "RESPONDER", state: "INVITED" }),
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_accept", {
    ...invitationAcceptResult(),
    sessionId: "sess_other_012345",
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_accept", {
    ...invitationAcceptResult(),
    roleGrant: grantFor({ role: "RESPONDER", allowedTools: ["agent_handshake_session_next"] }),
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_accept", {
    ...invitationAcceptResult(),
    roleGrant: grantFor({
      role: "RESPONDER",
      allowedTools: [...HANDSHAKE_V3_RESPONDER_REQUIRED_TOOLS, "agent_handshake_operator_request"],
    }),
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_accept", {
    ...invitationAcceptResult(),
    session: sessionFor({
      role: "RESPONDER",
      state: "CLAIMED",
      allowedTransitions: ["CLAIM_INVITATION", "FAIL_CLOSED", "CANCEL", "EXPIRE", "REVOKE"],
    }),
  }), { code: "SCHEMA_INVALID" });
});

test("tenantRelation is exact digest-only metadata", () => {
  const relation = validateHandshakeV3Def("tenantRelation", tenantRelationSample("INITIATOR_CREATED"));
  assert.equal(relation.visibility, "CREATOR_VIEW");
  assert.throws(() => validateHandshakeV3Def("tenantRelation", {
    ...tenantRelationSample("INITIATOR_CREATED"),
    rawTenantId: "tenant-secret",
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3Def("tenantRelation", {
    ...tenantRelationSample("INITIATOR_CREATED"),
    localTenantDigest: "tenant-raw",
  }), { code: "SCHEMA_INVALID" });
  const missingDigest = tenantRelationSample("INITIATOR_CREATED");
  delete missingDigest.counterpartyTenantDigest;
  assert.throws(() => validateHandshakeV3Def("tenantRelation", missingDigest), { code: "SCHEMA_INVALID" });
});

test("invitation list supports read-only token inspection with immutable policy details", () => {
  const policy = policySample();
  const byCursor = validateHandshakeV3ToolInput("agent_handshake_invitation_list", {
    cursor: "cursor_invite_012345",
    states: ["ISSUED"],
    limit: 20,
  });
  const byToken = validateHandshakeV3ToolInput("agent_handshake_invitation_list", {
    invitationToken: "tok_external_012345",
  });
  const inspected = validateHandshakeV3ToolResult("agent_handshake_invitation_list", {
    invitations: [{
      invitationId: "inv_external_012345",
      invitationToken: "tok_external_012345",
      state: "ISSUED",
      policy,
      policyDigest: digest,
      statementDigest: digestB,
      responderRole: "RESPONDER",
      responderBinding: "FIRST_AUTHENTICATED_CLAIM",
      expiresAt: later,
      protocolVersion: "3.0",
      schemaVersion: "3.0.0-draft.2",
      trustRootIds: ["root-2026-08"],
    }],
  });

  assert.equal(byCursor.input.cursor, "cursor_invite_012345");
  assert.equal(byToken.input.invitationToken, "tok_external_012345");
  assert.deepEqual(inspected.invitations[0].policy, policy);
  assert.equal(inspected.invitations[0].state, "ISSUED");

  assert.throws(() => validateHandshakeV3ToolInput("agent_handshake_invitation_list", {
    cursor: "cursor_invite_012345",
    invitationToken: "tok_external_012345",
  }), { code: "SCHEMA_INVALID" });
});

test("session next exposes an exhaustive machine-readable nextAction", () => {
  assert.equal(validateHandshakeV3ToolResult("agent_handshake_session_next", nextResult({
    state: "CLAIMED",
    nextAction: "WAIT",
    retryAfterMs: 1000,
  })).nextAction, "WAIT");
  assert.equal(validateHandshakeV3ToolResult("agent_handshake_session_next", nextResult({
    state: "PROPOSAL_PENDING",
    nextAction: "SIGN_AND_SUBMIT",
    pendingSigningRequest: signingRequestSample("PROPOSAL", "INITIATOR", 1),
    retryAfterMs: 0,
  })).nextAction, "SIGN_AND_SUBMIT");
  assert.equal(validateHandshakeV3ToolResult("agent_handshake_session_next", nextResult({
    state: "ACCEPTANCE_PENDING",
    nextAction: "SUBMIT_CHECKPOINT",
    pendingSigningRequest: signingRequestSample("EVIDENCE", "RESPONDER", 1),
    retryAfterMs: 0,
  })).nextAction, "SUBMIT_CHECKPOINT");
  assert.equal(validateHandshakeV3ToolResult("agent_handshake_session_next", nextResult({
    state: "CERTIFICATE_ISSUED",
    nextAction: "FETCH_RESULT",
    retryAfterMs: 0,
  })).nextAction, "FETCH_RESULT");
  assert.equal(validateHandshakeV3ToolResult("agent_handshake_session_next", nextResult({
    state: "CONTINUATION_ISSUED",
    nextAction: "STOP_AFTER_VERIFICATION",
    retryAfterMs: 0,
  })).nextAction, "STOP_AFTER_VERIFICATION");
  assert.equal(validateHandshakeV3ToolResult("agent_handshake_session_next", nextResult({
    state: "CANCELLED",
    nextAction: "TERMINAL",
    retryAfterMs: 0,
  })).nextAction, "TERMINAL");

  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_session_next", {
    changed: true,
    session: sessionSample(),
    events: [],
    retryAfterMs: 0,
  }), { code: "SCHEMA_INVALID" });
});

test("session next rejects inconsistent nextAction state and signing request pairings", () => {
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_session_next", nextResult({
    state: "PROPOSAL_PENDING",
    nextAction: "WAIT",
    retryAfterMs: 1000,
  })), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_session_next", nextResult({
    state: "PROPOSAL_PENDING",
    nextAction: "SIGN_AND_SUBMIT",
    retryAfterMs: 0,
  })), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_session_next", nextResult({
    state: "PROPOSAL_PENDING",
    nextAction: "SIGN_AND_SUBMIT",
    pendingSigningRequest: signingRequestSample("ACCEPTANCE", "RESPONDER", 1),
    retryAfterMs: 0,
  })), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_session_next", nextResult({
    state: "CERTIFICATE_ISSUED",
    nextAction: "FETCH_RESULT",
    pendingSigningRequest: signingRequestSample("EVIDENCE", "INITIATOR", 1),
    retryAfterMs: 0,
  })), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_session_next", nextResult({
    state: "CLAIMED",
    nextAction: "WAIT",
    retryAfterMs: 0,
  })), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_session_next", nextResult({
    state: "CANCELLED",
    nextAction: "WAIT",
    retryAfterMs: 1000,
  })), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_session_next", nextResult({
    state: "PROPOSAL_PENDING",
    nextAction: "SIGN_AND_SUBMIT",
    pendingSigningRequest: signingRequestSample("PROPOSAL", "INITIATOR", 1),
    retryAfterMs: 0,
    allowedTransitions: ["SUBMIT_ACCEPTANCE", "FAIL_CLOSED", "CANCEL", "EXPIRE"],
  })), { code: "SCHEMA_INVALID" });
});

test("session cancel is a role-bound input requiring roleGrantId", () => {
  const input = validateHandshakeV3ToolInput("agent_handshake_session_cancel", {
    sessionId: "sess_cancel_012345",
    roleGrantId: "grant_cancel_012345",
    reasonCode: "AGENT_CANCELLED",
    idempotencyKey: "idem.cancel.012345",
    expectedStateVersion: 2,
  });

  assert.equal(input.input.roleGrantId, "grant_cancel_012345");
  assert.throws(() => validateHandshakeV3ToolInput("agent_handshake_session_cancel", {
    sessionId: "sess_cancel_012345",
    reasonCode: "AGENT_CANCELLED",
    idempotencyKey: "idem.cancel.012345",
    expectedStateVersion: 2,
  }), { code: "SCHEMA_INVALID" });
});

test("documented external-agent response shapes are schema-reachable without shared controller state", () => {
  const policy = policySample();
  const sessionId = "sess_reachability_012345";
  const initiatorGrant = {
    ...grantFor({ role: "INITIATOR", sessionId }),
    roleGrantId: "grant_initiator_012345",
    principalDigest: digest,
    proofKeyThumbprint: digestB,
  };
  const responderGrant = {
    ...grantFor({ role: "RESPONDER", sessionId }),
    roleGrantId: "grant_responder_012345",
    principalDigest: digestB,
    proofKeyThumbprint: digest,
  };
  const invitedSession = sessionFor({
    sessionId,
    role: "INITIATOR",
    state: "INVITED",
    policy,
    policyDigest: digest,
  });
  const create = validateHandshakeV3ToolResult("agent_handshake_invitation_create", {
    invitationId: "inv_reachability_012345",
    invitationToken: "tok_reachability_012345",
    sessionId,
    roleGrant: initiatorGrant,
    tenantRelation: tenantRelationSample("INITIATOR_CREATED"),
    session: invitedSession,
    policyDigest: digest,
    statementDigest: digestB,
    state: "ISSUED",
    expiresAt: later,
  });
  const inspect = validateHandshakeV3ToolResult("agent_handshake_invitation_list", {
    invitations: [{
      invitationId: "inv_reachability_012345",
      invitationToken: "tok_reachability_012345",
      state: "ISSUED",
      policy,
      policyDigest: digest,
      statementDigest: digestB,
      responderRole: "RESPONDER",
      responderBinding: "FIRST_AUTHENTICATED_CLAIM",
      expiresAt: later,
      protocolVersion: "3.0",
      schemaVersion: "3.0.0-draft.2",
      trustRootIds: ["root-2026-08"],
    }],
  });
  const accept = validateHandshakeV3ToolResult("agent_handshake_invitation_accept", {
    sessionId,
    roleGrant: responderGrant,
    tenantRelation: tenantRelationSample("RESPONDER_ACCEPTED"),
    session: sessionFor({ sessionId, role: "RESPONDER", state: "CLAIMED", policy, policyDigest: digest }),
  });

  assert.equal(create.roleGrant.role, "INITIATOR");
  assert.equal(inspect.invitations[0].state, "ISSUED");
  assert.equal(accept.roleGrant.role, "RESPONDER");
  assert.equal(validateHandshakeV3ToolInput("agent_handshake_session_join", {
    sessionId,
    roleGrantId: create.roleGrant.roleGrantId,
    party: partySample("INITIATOR", digest),
    policyDigest: inspect.invitations[0].policyDigest,
    nonceCommitment: digest,
    idempotencyKey: "idem.join.initiator",
    expectedStateVersion: 1,
  }).input.roleGrantId, create.roleGrant.roleGrantId);
  assert.equal(validateHandshakeV3ToolInput("agent_handshake_session_join", {
    sessionId,
    roleGrantId: accept.roleGrant.roleGrantId,
    party: partySample("RESPONDER", digestB),
    policyDigest: inspect.invitations[0].policyDigest,
    nonceCommitment: digestB,
    idempotencyKey: "idem.join.responder",
    expectedStateVersion: 1,
  }).input.roleGrantId, accept.roleGrant.roleGrantId);
});

test("schema engine validates all 16 tool input and result schemas", () => {
  for (const tool of schema.tools) {
    const input = sampleForSchema(tool.inputSchema);
    const result = tool.name === "agent_handshake_invitation_create"
      ? invitationCreateResult()
      : tool.name === "agent_handshake_invitation_accept"
        ? invitationAcceptResult()
        : tool.name === "agent_handshake_session_next"
          ? nextResult({ state: "CLAIMED", nextAction: "WAIT", retryAfterMs: 1000 })
          : sampleForSchema(tool.resultSchema);
    assert.equal(validateHandshakeV3ToolInput(tool.name, input).tool, tool.name);
    assert.deepEqual(validateHandshakeV3ToolResult(tool.name, result), result);
    assert.throws(() => validateHandshakeV3ToolInput(tool.name, { ...input, extra: true }), { code: "SCHEMA_INVALID" }, `${tool.name} input extra`);
    if (tool.resultSchema.type === "object") {
      assert.throws(() => validateHandshakeV3ToolResult(tool.name, { ...result, extra: true }), { code: "SCHEMA_INVALID" }, `${tool.name} result extra`);
    }
  }
});

test("schema engine rejects accessors, proxies, bad enums, patterns, uniqueness, and oneOf violations", () => {
  assert.throws(() => validateHandshakeV3Def("signedAction", {
    signingRequestId: opaque,
    signingDigest: digest,
    signerKeyId: "key",
    algorithm: "P-256",
    signature: "0".repeat(32),
  }), { code: "SCHEMA_INVALID" });

  assert.throws(() => validateHandshakeV3Def("policy", {
    scope: ["duplicate", "duplicate"],
    constraints: {},
    externalBusinessActionsAllowed: false,
    expiresAt: later,
  }), { code: "SCHEMA_INVALID" });

  assert.throws(() => validateHandshakeV3ToolInput("agent_handshake_invitation_accept", {
    invitationId: opaque,
    invitationToken: opaque,
    party: sampleForSchema(schema.$defs.party),
    acceptedPolicyDigest: digest,
    idempotencyKey: "idem.accept.12345",
  }), { code: "SCHEMA_INVALID" });

  const accessor = {};
  Object.defineProperty(accessor, "operationId", { enumerable: true, get() { return opaque; } });
  Object.assign(accessor, { eventDigest: digest, stateVersion: 1, recordedAt: later });
  assert.throws(() => validateHandshakeV3Def("receipt", accessor), { code: "SCHEMA_INVALID" });

  const proxy = new Proxy(sampleForSchema(schema.$defs.receipt), {
    ownKeys() {
      throw new Error("proxy trap must not escape");
    },
  });
  assert.throws(() => validateHandshakeV3Def("receipt", proxy), { code: "SCHEMA_INVALID" });

  const prototypeProxy = new Proxy(sampleForSchema(schema.$defs.receipt), {
    getPrototypeOf() {
      throw new Error("getPrototypeOf trap must not escape");
    },
  });
  assert.throws(() => validateHandshakeV3Def("receipt", prototypeProxy), { code: "SCHEMA_INVALID" });
});

test("date-time format implements RFC3339 fractional seconds and offsets", () => {
  for (const value of [
    "2026-08-29T20:00:00Z",
    "2026-08-29t20:00:00z",
    "2026-08-29T20:00:00.123Z",
    "2026-08-29t20:00:00.123z",
    "2026-08-29T20:00:60Z",
    "2026-08-29t20:00:60z",
    "2026-08-29T20:00:00+00:00",
    "2026-08-29T12:30:45.123456-07:30",
  ]) {
    assert.equal(validateHandshakeV3Schema({ type: "string", format: "date-time" }, value), value);
  }

  for (const value of [
    "2026-02-29T20:00:00Z",
    "2024-02-29T24:00:00Z",
    "2026-08-29T20:60:00Z",
    "2026-08-29T20:00:61Z",
    "2026-08-29T20:00:00+24:00",
    "2026-08-29T20:00:00+07:60",
    "2026-08-29 20:00:00Z",
    "2026-08-29T20:00Z",
  ]) {
    assert.throws(() => validateHandshakeV3Schema({ type: "string", format: "date-time" }, value), { code: "SCHEMA_INVALID" }, value);
  }
});

test("operator-only scopes never satisfy role tool inputs", () => {
  assert.throws(
    () => validateHandshakeV3ToolInput("agent_handshake_session_next", {
      sessionId: opaque,
      roleGrantId: opaque,
      eventCursor: opaque,
    }, { tokenScopes: ["handshake.operator.expire", "handshake.operator.cancel"] }),
    { code: "SCOPE_DENIED" },
  );
});
