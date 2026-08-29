import contractSchema from "../../schemas/standalone-handshake-v3-contract.schema.json" with { type: "json" };

import { HANDSHAKE_V3_ROLE_TOOLS, fail } from "./constants.mjs";
import { parseHandshakeV3Rfc3339ToEpochMilliseconds } from "./time.mjs";

const BUSINESS_CONTENT_KEYS = new Set([
  "businessContent",
  "canonicalPayload",
  "payload",
  "continuationPayload",
]);

export const HANDSHAKE_V3_CONTRACT_SCHEMA = deepFreeze(contractSchema);
export const HANDSHAKE_V3_TOOL_NAMES = Object.freeze(contractSchema.tools.map((tool) => tool.name));

export function deepFreeze(value) {
  if (value && typeof value === "object") {
    if (!Object.isFrozen(value)) Object.freeze(value);
    for (const nested of Object.values(value)) {
      deepFreeze(nested);
    }
  }
  return value;
}

function schemaInvalid() {
  fail("SCHEMA_INVALID");
}

function normalizeSchema(schema) {
  if (schema === true) return {};
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) schemaInvalid();
  return schema;
}

function resolveRef(ref) {
  if (ref === "#/responseEnvelope") return contractSchema.responseEnvelope;
  if (ref === "#/errorCodes") return contractSchema.errorCodes;
  if (ref.startsWith("#/$defs/")) {
    const name = ref.slice("#/$defs/".length);
    const definition = contractSchema.$defs[name];
    if (!definition) schemaInvalid();
    return definition;
  }
  schemaInvalid();
}

function isPlainJsonObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  let prototype;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    schemaInvalid();
  }
  return prototype === Object.prototype || prototype === null;
}

function isValidRfc3339DateTime(value) {
  try {
    parseHandshakeV3Rfc3339ToEpochMilliseconds(value);
    return true;
  } catch {
    return false;
  }
}

function safeOwnKeys(value) {
  try {
    return Reflect.ownKeys(value);
  } catch {
    schemaInvalid();
  }
}

function safeDescriptor(value, key) {
  try {
    return Object.getOwnPropertyDescriptor(value, key);
  } catch {
    schemaInvalid();
  }
}

function assertObjectSafety(value) {
  if (!isPlainJsonObject(value)) schemaInvalid();
  const clone = {};
  for (const key of safeOwnKeys(value)) {
    if (typeof key !== "string" || BUSINESS_CONTENT_KEYS.has(key)) schemaInvalid();
    const descriptor = safeDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) schemaInvalid();
    clone[key] = descriptor.value;
  }
  return clone;
}

function cloneSafeJson(value, ancestors = new Set()) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) schemaInvalid();
    return value;
  }
  if (typeof value !== "object") schemaInvalid();
  if (ancestors.has(value)) schemaInvalid();

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = safeOwnKeys(value);
      for (const key of keys) {
        if (key === "length") continue;
        if (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length) schemaInvalid();
        const descriptor = safeDescriptor(value, key);
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) schemaInvalid();
      }
      const output = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) schemaInvalid();
        output.push(cloneSafeJson(value[index], ancestors));
      }
      return deepFreeze(output);
    }

    const source = assertObjectSafety(value);
    const output = {};
    for (const [key, entry] of Object.entries(source)) {
      output[key] = cloneSafeJson(entry, ancestors);
    }
    return deepFreeze(output);
  } finally {
    ancestors.delete(value);
  }
}

function validateString(value, schema) {
  if (typeof value !== "string") schemaInvalid();
  if (schema.minLength !== undefined && value.length < schema.minLength) schemaInvalid();
  if (schema.maxLength !== undefined && value.length > schema.maxLength) schemaInvalid();
  if (schema.pattern && !(new RegExp(schema.pattern).test(value))) schemaInvalid();
  if (schema.format === "date-time") {
    if (!isValidRfc3339DateTime(value)) schemaInvalid();
  }
  if (schema.format === "uuid") {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) schemaInvalid();
  }
  return value;
}

function validateNumber(value, schema) {
  if (typeof value !== "number" || !Number.isFinite(value)) schemaInvalid();
  const types = Array.isArray(schema.type) ? schema.type : [schema.type];
  if (types.includes("integer") && !Number.isInteger(value)) schemaInvalid();
  if (schema.minimum !== undefined && value < schema.minimum) schemaInvalid();
  if (schema.maximum !== undefined && value > schema.maximum) schemaInvalid();
  return value;
}

function stableUniquenessKey(value) {
  if (value && typeof value === "object") {
    return JSON.stringify(value, Object.keys(value).sort());
  }
  return `${typeof value}:${String(value)}`;
}

function validateArray(schema, value) {
  if (!Array.isArray(value)) schemaInvalid();
  if (schema.minItems !== undefined && value.length < schema.minItems) schemaInvalid();
  if (schema.maxItems !== undefined && value.length > schema.maxItems) schemaInvalid();
  if (schema.uniqueItems) {
    const seen = new Set();
    for (const item of value) {
      const key = stableUniquenessKey(item);
      if (seen.has(key)) schemaInvalid();
      seen.add(key);
    }
  }
  return deepFreeze(value.map((item) => validateAgainstSchema(schema.items ?? {}, item)));
}

function validateObject(schema, value) {
  const source = assertObjectSafety(value);
  if (schema.maxProperties !== undefined && Object.keys(source).length > schema.maxProperties) schemaInvalid();
  if (schema.required) {
    for (const key of schema.required) {
      if (!Object.hasOwn(source, key)) schemaInvalid();
    }
  }
  if (!schema.properties && schema.additionalProperties === undefined) {
    return cloneSafeJson(value);
  }
  const properties = schema.properties ?? {};
  const output = {};
  for (const [key, entry] of Object.entries(source)) {
    if (properties[key]) {
      output[key] = validateAgainstSchema(properties[key], entry);
    } else if (schema.additionalProperties === false) {
      schemaInvalid();
    } else if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
      output[key] = validateAgainstSchema(schema.additionalProperties, entry);
    } else {
      output[key] = entry;
    }
  }
  return deepFreeze(output);
}

function matches(schema, value) {
  try {
    validateAgainstSchema(schema, value);
    return true;
  } catch (error) {
    if (error?.code === "SCHEMA_INVALID") return false;
    throw error;
  }
}

function validateAgainstSchema(schemaInput, value) {
  const schema = normalizeSchema(schemaInput);
  if (schema.$ref) return validateAgainstSchema(resolveRef(schema.$ref), value);
  if (schema.const !== undefined && value !== schema.const) schemaInvalid();
  if (schema.enum && !schema.enum.includes(value)) schemaInvalid();
  if (schema.not && matches(schema.not, value)) schemaInvalid();
  if (schema.anyOf && !schema.anyOf.some((option) => matches(option, value))) schemaInvalid();
  if (schema.oneOf && schema.oneOf.filter((option) => matches(option, value)).length !== 1) schemaInvalid();

  const types = Array.isArray(schema.type) ? schema.type : schema.type ? [schema.type] : [];
  if (types.length > 0) {
    const typeMatches = types.some((type) => {
      if (type === "null") return value === null;
      if (type === "array") return Array.isArray(value);
      if (type === "object") return isPlainJsonObject(value);
      if (type === "integer") return typeof value === "number" && Number.isInteger(value);
      return typeof value === type;
    });
    if (!typeMatches) schemaInvalid();
  }

  if (typeof value === "string") return validateString(value, schema);
  if (typeof value === "number") return validateNumber(value, schema);
  if (typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return validateArray(schema, value);
  if (isPlainJsonObject(value)) return validateObject(schema, value);
  schemaInvalid();
}

export function validateHandshakeV3Schema(schema, value) {
  return validateAgainstSchema(schema, value);
}

export function validateHandshakeV3Def(defName, value) {
  const definition = contractSchema.$defs[defName];
  if (!definition) schemaInvalid();
  return validateAgainstSchema(definition, value);
}

export function validateHandshakeV3ResponseEnvelope(value) {
  return validateAgainstSchema(contractSchema.responseEnvelope, value);
}

function toolSchema(toolName, kind) {
  const tool = contractSchema.tools.find((candidate) => candidate.name === toolName);
  if (!tool) schemaInvalid();
  return tool[`${kind}Schema`];
}

export function validateHandshakeV3ToolInput(toolName, input, context = {}) {
  if (HANDSHAKE_V3_ROLE_TOOLS.includes(toolName) && context.tokenScopes?.every((scope) => scope.startsWith("handshake.operator."))) {
    fail("SCOPE_DENIED");
  }
  return deepFreeze({ tool: toolName, input: validateAgainstSchema(toolSchema(toolName, "input"), input) });
}

export function validateHandshakeV3ToolResult(toolName, result) {
  return validateAgainstSchema(toolSchema(toolName, "result"), result);
}

export function validateHandshakeV3Fixture(fixture) {
  if (fixture.schemaRef === "#/$defs/signingRequest") {
    validateHandshakeV3SigningRequest(fixture.value);
  } else if (fixture.schemaRef === "#/$defs/signedAction") {
    validateHandshakeV3SignedAction(fixture.value);
  } else if (fixture.schemaRef === "#/responseEnvelope") {
    validateHandshakeV3ResponseEnvelope(fixture.value);
  } else if (fixture.tool) {
    validateHandshakeV3ToolInput(fixture.tool, fixture.input, { tokenScopes: fixture.tokenScopes });
  } else if (fixture.resultTool) {
    validateHandshakeV3ToolResult(fixture.resultTool, fixture.value);
  } else {
    schemaInvalid();
  }
  return deepFreeze({ valid: true, id: fixture.id });
}

export const validateHandshakeV3Policy = (value) => validateHandshakeV3Def("policy", value);
export const validateHandshakeV3Party = (value) => validateHandshakeV3Def("party", value);
export const validateHandshakeV3RoleGrant = (value) => validateHandshakeV3Def("roleGrant", value);
export const validateHandshakeV3SigningRequest = (value) => validateHandshakeV3Def("signingRequest", value);
export const validateHandshakeV3SignedAction = (value) => validateHandshakeV3Def("signedAction", value);
export const validateHandshakeV3Receipt = (value) => validateHandshakeV3Def("receipt", value);
export const validateHandshakeV3FailureReceipt = (value) => validateHandshakeV3Def("failureReceipt", value);
export const validateHandshakeV3CallbackEvent = (value) => validateHandshakeV3Def("callbackEvent", value);
export const validateHandshakeV3Session = (value) => validateHandshakeV3Def("session", value);
export const validateHandshakeV3Certificate = (value) => validateHandshakeV3Def("certificate", value);
export const validateHandshakeV3Continuation = (value) => validateHandshakeV3Def("continuation", value);
