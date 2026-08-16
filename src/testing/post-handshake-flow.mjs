import { assertSecretFree } from "../core/redact.mjs";

export const FACILITATED_A2A_RESULT_SCHEMA =
  "agent-contract.facilitated-a2a-result/v1";

const ROLES = Object.freeze(["initiator", "responder"]);
const ENVIRONMENT_PREFIX = "AGENT_CONTRACT_A2A_";

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function frozenPublicValue(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(frozenPublicValue));
  if (!isPlainObject(value)) {
    if (["string", "number", "boolean"].includes(typeof value) || value === null) return value;
    throw new TypeError("Post-handshake result must contain only public JSON values.");
  }
  return Object.freeze(Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, frozenPublicValue(entry)]),
  ));
}

function cleanEnvironment(value) {
  if (!isPlainObject(value)) throw new TypeError("Continuation environment must be an object.");
  const entries = Object.entries(value);
  for (const [key, entry] of entries) {
    if (!key.startsWith(ENVIRONMENT_PREFIX)) {
      throw new TypeError(`Continuation environment keys must begin ${ENVIRONMENT_PREFIX}.`);
    }
    if (typeof entry !== "string" || entry.length === 0) {
      throw new TypeError("Continuation environment values must be nonempty strings.");
    }
  }
  return Object.freeze(Object.fromEntries(entries));
}

export function createPostHandshakeContinueRole({ roles, invoke } = {}) {
  if (!isPlainObject(roles) || typeof invoke !== "function") {
    throw new TypeError("Post-handshake role contexts and invoke function are required.");
  }
  for (const role of ROLES) {
    const context = roles[role];
    if (
      !isPlainObject(context) ||
      !["codex", "claude"].includes(context.client) ||
      typeof context.workspace !== "string" ||
      context.workspace.length === 0
    ) {
      throw new TypeError(`Invalid ${role} continuation context.`);
    }
  }

  return async function continueRole(role, { environment = {}, prompt } = {}) {
    if (!ROLES.includes(role)) throw new TypeError("Unknown post-handshake role.");
    if (typeof prompt !== "string" || prompt.trim().length === 0) {
      throw new TypeError("Continuation prompt must be a nonempty string.");
    }
    const context = roles[role];
    return invoke(Object.freeze({
      role,
      client: context.client,
      workspace: context.workspace,
      ...(context.claudeSessionId === undefined ? {} : { claudeSessionId: context.claudeSessionId }),
      prompt,
      environment: cleanEnvironment(environment),
    }));
  };
}

export function validateFacilitatedA2AResult(result, secretCanaries = []) {
  if (!isPlainObject(result) || result.schema !== FACILITATED_A2A_RESULT_SCHEMA) {
    throw new TypeError(`Post-handshake result schema must be ${FACILITATED_A2A_RESULT_SCHEMA}.`);
  }
  assertSecretFree(result, secretCanaries);
  return frozenPublicValue(result);
}

export async function runPostHandshakeFlow({
  flow,
  evidence,
  continueRole,
  secretCanaries = [],
} = {}) {
  if (flow === null || flow === undefined) return null;
  if (typeof flow !== "function" || typeof continueRole !== "function") {
    throw new TypeError("Post-handshake flow and continuation function are required.");
  }
  if (!isPlainObject(evidence) || !Object.isFrozen(evidence)) {
    throw new TypeError("Post-handshake evidence must be a frozen public object.");
  }
  const result = await flow(Object.freeze({ evidence, continueRole }));
  return validateFacilitatedA2AResult(result, secretCanaries);
}
