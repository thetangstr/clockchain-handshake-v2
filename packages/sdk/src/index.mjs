import contractSchema from "@clockchain/handshake-protocol/schemas/standalone-handshake-v3-contract.schema.json" with { type: "json" };
import {
  createHandshakeV3SigningRequest,
  fail,
  validateHandshakeV3ToolInput,
  validateHandshakeV3ToolResult,
  verifyHandshakeV3Certificate,
  verifyHandshakeV3Continuation,
} from "@clockchain/handshake-protocol/v3";

function deepFreeze(value) {
  if (value && typeof value === "object") {
    if (!Object.isFrozen(value)) Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}

const CONTRACT = deepFreeze({
  protocolVersion: contractSchema.protocolVersion,
  schemaVersion: contractSchema.schemaVersion,
  tools: contractSchema.tools.map((tool) => tool.name),
  schema: contractSchema,
});

const TOOL_DESCRIPTORS = deepFreeze(Object.fromEntries(contractSchema.tools.map((tool) => [tool.name, {
  name: tool.name,
  description: tool.description,
  inputSchema: tool.inputSchema,
  resultSchema: tool.resultSchema,
}])));

function requireCallback(value) {
  if (typeof value !== "function") fail("RESULT_VERIFICATION_FAILED");
  return value;
}

function cliShapeInvalid() {
  fail("SCHEMA_INVALID");
}

function safeOwnKeys(value) {
  try {
    return Reflect.ownKeys(value);
  } catch {
    cliShapeInvalid();
  }
}

function safeDescriptor(value, key) {
  try {
    return Object.getOwnPropertyDescriptor(value, key);
  } catch {
    cliShapeInvalid();
  }
}

function assertPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) cliShapeInvalid();
  let prototype;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    cliShapeInvalid();
  }
  if (prototype !== Object.prototype && prototype !== null) cliShapeInvalid();
}

function cloneCliJson(value, ancestors = new Set()) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) cliShapeInvalid();
    return value;
  }
  if (typeof value !== "object") cliShapeInvalid();
  if (ancestors.has(value)) cliShapeInvalid();
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = safeOwnKeys(value);
      for (const key of keys) {
        if (key === "length") continue;
        if (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length) cliShapeInvalid();
        const descriptor = safeDescriptor(value, key);
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) cliShapeInvalid();
      }
      const output = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) cliShapeInvalid();
        output.push(cloneCliJson(value[index], ancestors));
      }
      return deepFreeze(output);
    }
    assertPlainObject(value);
    const output = {};
    for (const key of safeOwnKeys(value)) {
      if (typeof key !== "string") cliShapeInvalid();
      const descriptor = safeDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) cliShapeInvalid();
      output[key] = cloneCliJson(descriptor.value, ancestors);
    }
    return deepFreeze(output);
  } finally {
    ancestors.delete(value);
  }
}

function cloneCliObject(value) {
  const cloned = cloneCliJson(value);
  assertPlainObject(cloned);
  return cloned;
}

function assertExactKeys(value, keys) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) cliShapeInvalid();
}

export function getHandshakeV3Contract() {
  return CONTRACT;
}

export function listHandshakeV3Tools() {
  return CONTRACT.tools;
}

export function getHandshakeV3ToolDescriptor(toolName) {
  const descriptor = TOOL_DESCRIPTORS[toolName];
  if (!descriptor) fail("SCHEMA_INVALID");
  return descriptor;
}

export function validateHandshakeV3SdkToolInput(toolName, input, context) {
  return validateHandshakeV3ToolInput(toolName, input, context);
}

export function validateHandshakeV3SdkToolResult(toolName, result) {
  return validateHandshakeV3ToolResult(toolName, result);
}

export function prepareHandshakeV3Signing(input) {
  const request = createHandshakeV3SigningRequest(input);
  return deepFreeze({
    request,
    bytesBase64Url: request.canonicalBytesBase64Url,
    signingDigest: request.signingDigest,
    externalBusinessActionPerformed: false,
  });
}

export async function verifyHandshakeV3SdkCertificate(input) {
  return verifyHandshakeV3Certificate({
    ...input,
    verifyIssuerSignature: requireCallback(input?.verifyIssuerSignature),
    getRevocationStatus: requireCallback(input?.getRevocationStatus),
  });
}

export async function verifyHandshakeV3SdkContinuation(input) {
  return verifyHandshakeV3Continuation({
    ...input,
    verifyIssuerSignature: requireCallback(input?.verifyIssuerSignature),
    getRevocationStatus: requireCallback(input?.getRevocationStatus),
    checkAndRecordReplay: requireCallback(input?.checkAndRecordReplay),
  });
}

export function validateHandshakeV3CliResultShape(value) {
  const cloned = cloneCliObject(value);
  if (typeof cloned.ok !== "boolean") cliShapeInvalid();
  if (typeof cloned.command !== "string" || cloned.command.length === 0) cliShapeInvalid();
  if (cloned.externalBusinessActionPerformed !== false) cliShapeInvalid();
  if (cloned.ok) {
    assertExactKeys(cloned, [
      "ok",
      "command",
      "verificationMode",
      "clockchainTrustVerified",
      "externalBusinessActionPerformed",
      "result",
    ]);
    if (cloned.verificationMode !== "explicit_fixture_only") cliShapeInvalid();
    if (cloned.clockchainTrustVerified !== false) cliShapeInvalid();
  } else {
    assertExactKeys(cloned, ["ok", "command", "externalBusinessActionPerformed", "error"]);
    if (!cloned.error || typeof cloned.error !== "object" || Array.isArray(cloned.error)) cliShapeInvalid();
    if (typeof cloned.error.code !== "string") cliShapeInvalid();
  }
  return deepFreeze(cloned);
}
