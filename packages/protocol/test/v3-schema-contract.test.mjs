import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  HANDSHAKE_V3_CONTRACT_SCHEMA,
  HANDSHAKE_V3_ERROR_CODES,
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
const opaque = "opaque_identifier_123";
const later = "2026-08-29T21:00:00Z";

function roleGrantSample() {
  return sampleForSchema(schema.$defs.roleGrant);
}

function sessionSample() {
  return sampleForSchema(schema.$defs.session);
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
      return fragment.uniqueItems && typeof value === "string" ? `${value}_${index}` : value;
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
    schemaVersion: "3.0.0-draft.1",
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
    schemaVersion: "3.0.0-draft.1",
    toolsetDigest: digest,
    trustRootIds: ["root-2026-08"],
    limits: value,
  }), { code: "SCHEMA_INVALID" });
  assert.throws(() => validateHandshakeV3ToolResult("agent_handshake_invitation_accept", {
    sessionId: opaque,
    roleGrant: roleGrantSample(),
    tenantRelation: value,
    session: sessionSample(),
  }), { code: "SCHEMA_INVALID" });
}

test("constants mirror the normative schema enums exactly", () => {
  assert.deepEqual(HANDSHAKE_V3_CONTRACT_SCHEMA.errorCodes.enum, schema.errorCodes.enum);
  assert.deepEqual(HANDSHAKE_V3_ERROR_CODES, schema.errorCodes.enum);
  assert.deepEqual(HANDSHAKE_V3_SIGNING_ALGORITHMS, ["ES256K", "EdDSA", "ES256"]);
  assert.deepEqual(HANDSHAKE_V3_TOOL_NAMES, schema.tools.map((tool) => tool.name));
  assert.equal(HANDSHAKE_V3_TOOL_NAMES.length, 16);
  assert.equal(HANDSHAKE_V3_TOOL_NAMES.includes("agent_handshake_session_verify"), false);
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
    schemaVersion: "3.0.0-draft.1",
    toolsetDigest: digest,
    trustRootIds: ["root-2026-08"],
    limits: nested,
  }).limits, nested);
  assert.deepEqual(validateHandshakeV3ToolResult("agent_handshake_invitation_accept", {
    sessionId: opaque,
    roleGrant: roleGrantSample(),
    tenantRelation: nested,
    session: sessionSample(),
  }).tenantRelation, nested);

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

test("schema engine validates all 16 tool input and result schemas", () => {
  for (const tool of schema.tools) {
    const input = sampleForSchema(tool.inputSchema);
    const result = sampleForSchema(tool.resultSchema);
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
