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
  if (!value || typeof value !== "object" || Array.isArray(value)) cliShapeInvalid();
  if (typeof value.ok !== "boolean") cliShapeInvalid();
  if (typeof value.command !== "string" || value.command.length === 0) cliShapeInvalid();
  if (value.externalBusinessActionPerformed !== false) cliShapeInvalid();
  if (value.ok) {
    if (!Object.hasOwn(value, "result")) cliShapeInvalid();
    if (Object.hasOwn(value, "error")) cliShapeInvalid();
  } else {
    if (!value.error || typeof value.error !== "object" || Array.isArray(value.error)) cliShapeInvalid();
    if (typeof value.error.code !== "string") cliShapeInvalid();
  }
  return deepFreeze(value);
}
