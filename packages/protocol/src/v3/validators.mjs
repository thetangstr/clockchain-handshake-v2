import {
  HANDSHAKE_V3_STATES,
  HANDSHAKE_V3_OPERATOR_TOOLS,
  HANDSHAKE_V3_PROTOCOL_VERSION,
  HANDSHAKE_V3_ROLE_TOOLS,
  HANDSHAKE_V3_SCHEMA_VERSION,
  HANDSHAKE_V3_SIGNING_ALGORITHMS,
  fail,
} from "./constants.mjs";

const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ISO_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const BUSINESS_CONTENT_KEYS = new Set(["businessContent", "canonicalPayload", "payload", "message", "continuationPayload"]);

export function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) {
      deepFreeze(nested);
    }
  }
  return value;
}

export function cloneStrictRecord(value, allowedKeys, requiredKeys, code = "SCHEMA_INVALID") {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(code);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail(code);
  }
  const clone = {};
  for (const key of Reflect.ownKeys(value)) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      fail(code);
    }
    if (typeof key !== "string" || !descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
      fail(code);
    }
    if (!allowedKeys.includes(key) || BUSINESS_CONTENT_KEYS.has(key)) {
      fail(code);
    }
    clone[key] = descriptor.value;
  }
  for (const key of requiredKeys) {
    if (!Object.hasOwn(clone, key)) {
      fail(code);
    }
  }
  return clone;
}

export function assertDigest(value, code = "SCHEMA_INVALID") {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    fail(code);
  }
}

export function assertIsoDate(value, code = "SCHEMA_INVALID") {
  if (typeof value !== "string" || !ISO_DATE_PATTERN.test(value) || Number.isNaN(Date.parse(value))) {
    fail(code);
  }
}

export function assertString(value, code = "SCHEMA_INVALID") {
  if (typeof value !== "string" || value.length === 0) {
    fail(code);
  }
}

function assertSafeInteger(value, code = "SCHEMA_INVALID") {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(code);
  }
}

export function validateHandshakeV3SigningRequest(value) {
  const request = cloneStrictRecord(value, [
    "signingRequestId",
    "actionType",
    "domainSeparator",
    "canonicalization",
    "payloadSchemaId",
    "sessionId",
    "stateVersion",
    "role",
    "policyDigest",
    "statementDigest",
    "counterpartyDigest",
    "priorEventDigest",
    "evidenceDigest",
    "nonce",
    "issuedAt",
    "expiresAt",
    "canonicalBytesBase64Url",
    "signingDigest",
  ], [
    "signingRequestId",
    "actionType",
    "domainSeparator",
    "canonicalization",
    "payloadSchemaId",
    "sessionId",
    "stateVersion",
    "role",
    "policyDigest",
    "statementDigest",
    "nonce",
    "issuedAt",
    "expiresAt",
    "canonicalBytesBase64Url",
    "signingDigest",
  ]);
  for (const key of ["signingRequestId", "actionType", "domainSeparator", "canonicalization", "payloadSchemaId", "sessionId", "role", "nonce", "canonicalBytesBase64Url"]) {
    assertString(request[key]);
  }
  assertSafeInteger(request.stateVersion);
  for (const key of ["policyDigest", "statementDigest", "signingDigest", "counterpartyDigest", "priorEventDigest", "evidenceDigest"]) {
    if (request[key] !== undefined) {
      assertDigest(request[key]);
    }
  }
  assertIsoDate(request.issuedAt);
  assertIsoDate(request.expiresAt);
  return deepFreeze(request);
}

export function validateHandshakeV3SignedAction(value) {
  const action = cloneStrictRecord(value, [
    "signingRequestId",
    "signingDigest",
    "signerKeyId",
    "algorithm",
    "signature",
  ], [
    "signingRequestId",
    "signingDigest",
    "signerKeyId",
    "algorithm",
    "signature",
  ]);
  assertString(action.signingRequestId);
  assertString(action.signerKeyId);
  assertString(action.signature);
  assertDigest(action.signingDigest);
  if (!HANDSHAKE_V3_SIGNING_ALGORITHMS.includes(action.algorithm)) {
    fail("SCHEMA_INVALID");
  }
  return deepFreeze(action);
}

export function validateHandshakeV3RoleGrant(value, context = {}) {
  const grant = cloneStrictRecord(value, [
    "roleGrantId",
    "sessionId",
    "role",
    "principalDigest",
    "proofKeyThumbprint",
    "allowedTools",
    "issuedAt",
    "expiresAt",
    "recoveredWithoutMutation",
    "protocolStateMutated",
  ], [
    "roleGrantId",
    "sessionId",
    "role",
    "principalDigest",
    "proofKeyThumbprint",
    "allowedTools",
    "issuedAt",
    "expiresAt",
  ]);
  for (const key of ["roleGrantId", "sessionId", "role"]) {
    assertString(grant[key]);
  }
  assertDigest(grant.principalDigest);
  assertDigest(grant.proofKeyThumbprint);
  if (!Array.isArray(grant.allowedTools) || grant.allowedTools.some((tool) => typeof tool !== "string")) {
    fail("SCHEMA_INVALID");
  }
  assertIsoDate(grant.issuedAt);
  assertIsoDate(grant.expiresAt);
  if (context.sessionId && grant.sessionId !== context.sessionId) {
    fail("ROLE_GRANT_BOUNDARY_MISMATCH");
  }
  if (context.role && grant.role !== context.role) {
    fail("ROLE_GRANT_BOUNDARY_MISMATCH");
  }
  if (context.principalDigest && grant.principalDigest !== context.principalDigest) {
    fail("ROLE_GRANT_BOUNDARY_MISMATCH");
  }
  if (context.proofKeyThumbprint && grant.proofKeyThumbprint !== context.proofKeyThumbprint) {
    fail("ROLE_GRANT_BOUNDARY_MISMATCH");
  }
  if (context.tool && !grant.allowedTools.includes(context.tool)) {
    fail("ROLE_GRANT_TOOL_DENIED");
  }
  if (context.now && Date.parse(context.now) >= Date.parse(grant.expiresAt)) {
    fail("ROLE_GRANT_EXPIRED");
  }
  return deepFreeze(grant);
}

export function validateHandshakeV3Policy(value) {
  const policy = cloneStrictRecord(value, ["policyId", "scope", "expiresAt", "statementDigest", "policyDigest"], ["policyId", "scope", "expiresAt"]);
  assertString(policy.policyId);
  assertString(policy.scope);
  assertIsoDate(policy.expiresAt);
  if (policy.statementDigest) assertDigest(policy.statementDigest);
  if (policy.policyDigest) assertDigest(policy.policyDigest);
  return deepFreeze(policy);
}

export function validateHandshakeV3Party(value) {
  const party = cloneStrictRecord(value, ["role", "partyDigest", "principalDigest", "signingKeyId", "proofKeyThumbprint"], ["role", "partyDigest", "principalDigest", "signingKeyId"]);
  assertString(party.role);
  assertDigest(party.partyDigest);
  assertDigest(party.principalDigest);
  assertString(party.signingKeyId);
  if (party.proofKeyThumbprint) assertDigest(party.proofKeyThumbprint);
  return deepFreeze(party);
}

export function validateHandshakeV3Receipt(value) {
  const receipt = cloneStrictRecord(value, [
    "requestDigest",
    "stateVersion",
    "eventDigest",
    "recordedAt",
    "mutated",
  ], [
    "requestDigest",
    "stateVersion",
    "recordedAt",
    "mutated",
  ]);
  assertDigest(receipt.requestDigest);
  if (receipt.eventDigest) assertDigest(receipt.eventDigest);
  assertSafeInteger(receipt.stateVersion);
  assertIsoDate(receipt.recordedAt);
  if (typeof receipt.mutated !== "boolean") fail("SCHEMA_INVALID");
  return deepFreeze(receipt);
}

export function validateHandshakeV3FailureReceipt(value) {
  const receipt = cloneStrictRecord(value, [
    "requestDigest",
    "stateVersion",
    "recordedAt",
    "mutated",
  ], [
    "requestDigest",
    "stateVersion",
    "recordedAt",
    "mutated",
  ]);
  assertDigest(receipt.requestDigest);
  assertSafeInteger(receipt.stateVersion);
  assertIsoDate(receipt.recordedAt);
  if (receipt.mutated !== false) fail("SCHEMA_INVALID");
  return deepFreeze(receipt);
}

export function validateHandshakeV3CallbackEvent(value) {
  const event = cloneStrictRecord(value, [
    "eventId",
    "sessionId",
    "eventType",
    "eventDigest",
    "stateVersion",
    "occurredAt",
  ], [
    "eventId",
    "sessionId",
    "eventType",
    "eventDigest",
    "stateVersion",
    "occurredAt",
  ]);
  assertString(event.eventId);
  assertString(event.sessionId);
  assertString(event.eventType);
  assertDigest(event.eventDigest);
  assertSafeInteger(event.stateVersion);
  assertIsoDate(event.occurredAt);
  return deepFreeze(event);
}

export function validateHandshakeV3Session(value) {
  const session = cloneStrictRecord(value, [
    "sessionId",
    "state",
    "stateVersion",
    "tenantDigest",
    "createdAt",
    "expiresAt",
    "signedObjects",
  ], [
    "sessionId",
    "state",
    "stateVersion",
    "tenantDigest",
    "createdAt",
    "expiresAt",
  ]);
  assertString(session.sessionId);
  if (!HANDSHAKE_V3_STATES.includes(session.state)) fail("SCHEMA_INVALID");
  assertSafeInteger(session.stateVersion);
  assertDigest(session.tenantDigest);
  assertIsoDate(session.createdAt);
  assertIsoDate(session.expiresAt);
  if (session.signedObjects !== undefined && !Array.isArray(session.signedObjects)) fail("SCHEMA_INVALID");
  return deepFreeze(session);
}

export function validateHandshakeV3ResponseEnvelope(value) {
  const envelope = cloneStrictRecord(value, ["protocolVersion", "schemaVersion", "requestId", "serverTime", "result", "receipt", "error", "failureReceipt"], ["protocolVersion", "schemaVersion", "requestId", "serverTime"]);
  if (envelope.protocolVersion !== HANDSHAKE_V3_PROTOCOL_VERSION || envelope.schemaVersion !== HANDSHAKE_V3_SCHEMA_VERSION) {
    fail("SCHEMA_INVALID");
  }
  assertIsoDate(envelope.serverTime);
  const hasResult = envelope.result !== undefined;
  const hasReceipt = envelope.receipt !== undefined;
  const hasError = envelope.error !== undefined;
  const hasFailureReceipt = envelope.failureReceipt !== undefined;
  if (hasResult && (!hasReceipt || hasError || hasFailureReceipt)) {
    fail("SCHEMA_INVALID");
  }
  if (hasFailureReceipt && (!hasError || hasResult || hasReceipt)) {
    fail("SCHEMA_INVALID");
  }
  if (hasError && !hasFailureReceipt && (hasResult || hasReceipt)) {
    fail("SCHEMA_INVALID");
  }
  if (!hasResult && !hasError) {
    fail("SCHEMA_INVALID");
  }
  return deepFreeze(envelope);
}

export function validateHandshakeV3ToolInput(tool, input, context = {}) {
  if (HANDSHAKE_V3_ROLE_TOOLS.includes(tool)) {
    if (context.tokenScopes?.every((scope) => scope.startsWith("handshake.operator."))) {
      fail("SCOPE_DENIED");
    }
    const required = tool === "agent_handshake_session_submit"
      ? ["sessionId", "roleGrantId", "action", "idempotencyKey", "expectedStateVersion"]
      : ["sessionId", "roleGrantId"];
    const allowed = [...new Set([...required, "eventCursor", "waitTimeoutMs"])];
    const body = cloneStrictRecord(input, allowed, required);
    return deepFreeze({ tool, input: body });
  }
  if (tool === "agent_handshake_operator_request") {
    const body = cloneStrictRecord(input, ["sessionId", "action", "reasonCode", "observedStateVersion", "observedEventDigest", "idempotencyKey"], ["sessionId", "action", "reasonCode", "observedStateVersion", "observedEventDigest", "idempotencyKey"]);
    if (!["REQUEST_EXPIRY_EVALUATION", "REQUEST_CANCELLATION"].includes(body.action)) {
      fail("SCHEMA_INVALID");
    }
    return deepFreeze({ tool, input: body });
  }
  fail("SCHEMA_INVALID");
}

export function validateHandshakeV3ToolResult(tool, value) {
  if (tool === "agent_handshake_session_cancel") {
    const result = cloneStrictRecord(value, ["sessionId", "state", "stateVersion", "mutated"], ["sessionId", "state"]);
    return deepFreeze(result);
  }
  return deepFreeze(cloneStrictRecord(value, ["sessionId", "state", "stateVersion", "receipt"], ["sessionId"]));
}

export function validateHandshakeV3Fixture(fixture) {
  if (fixture.schemaRef === "#/$defs/signingRequest") {
    validateHandshakeV3SigningRequest(fixture.value);
  } else if (fixture.schemaRef === "#/responseEnvelope") {
    validateHandshakeV3ResponseEnvelope(fixture.value);
  } else if (fixture.tool) {
    validateHandshakeV3ToolInput(fixture.tool, fixture.input, { tokenScopes: fixture.tokenScopes });
  } else if (fixture.resultTool) {
    validateHandshakeV3ToolResult(fixture.resultTool, fixture.value);
  } else {
    fail("SCHEMA_INVALID");
  }
  return deepFreeze({ valid: true, id: fixture.id });
}
