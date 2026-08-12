import { randomUUID } from "node:crypto";

export const HARNESS_EVENT_SCHEMA = "clockchain.harness-event/v1";
export const RETAINED_LOCAL_ACTION_SCHEMA = "clockchain.retained-local-action/v1";

const ROLES = Object.freeze(["initiator", "responder"]);
const SHA = /^[0-9a-f]{64}$/;
const UUIDISH = /^[0-9a-f-]{36}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const SAFE_TEXT = /^[\x20-\x7e]{1,256}$/;
const ACTION_KEYS = Object.freeze([
  "actionId", "adapterPublicKey", "adapterRecordDigest", "adapterSignature", "commandLength",
  "commandSha256", "expiresAtMs", "issuedAtMs", "operation", "policyDigest", "requestDigest",
  "requestLength", "role", "schema", "sessionId",
]);
const EVENT_KEYS = Object.freeze([
  "evidenceRef", "harness", "publicSummary", "redacted", "role", "schema", "sequence",
  "sessionId", "timestampMs", "type",
]);

function fail() {
  throw new Error("Harness adapter contract validation failed safely.");
}

function rejectAuthorityFields(value) {
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) {
    for (const item of value) rejectAuthorityFields(item);
    return;
  }
  if (typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (/(?:private.?key|secret.?key|controller.?private.?key|signer)$/i.test(key)) fail();
    rejectAuthorityFields(child);
  }
}

function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) fail();
  return value;
}

function role(value) {
  if (!ROLES.includes(value)) fail();
  return value;
}

function digest(value) {
  if (typeof value !== "string" || !SHA.test(value)) fail();
  return value;
}

function timestamp(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail();
  return value;
}

function safeText(value) {
  if (typeof value !== "string" || !SAFE_TEXT.test(value) || /\/(?:Users|private|tmp|Volumes)\//.test(value)) fail();
  return value;
}

export function validateRetainedLocalAction(value) {
  const item = exactObject(value, ACTION_KEYS);
  if (
    item.schema !== RETAINED_LOCAL_ACTION_SCHEMA ||
    typeof item.sessionId !== "string" ||
    item.sessionId.length === 0 ||
    typeof item.actionId !== "string" ||
    item.actionId.length === 0 ||
    typeof item.operation !== "string" ||
    item.operation.length === 0 ||
    !Number.isSafeInteger(item.requestLength) ||
    item.requestLength < 1 ||
    !Number.isSafeInteger(item.commandLength) ||
    item.commandLength < 1 ||
    typeof item.adapterSignature !== "string" ||
    !BASE64.test(item.adapterSignature) ||
    Buffer.from(item.adapterSignature, "base64").length !== 64 ||
    typeof item.adapterPublicKey !== "string" ||
    !BASE64.test(item.adapterPublicKey) ||
    Buffer.from(item.adapterPublicKey, "base64").length !== 32
  ) fail();
  const issuedAtMs = timestamp(item.issuedAtMs);
  const expiresAtMs = timestamp(item.expiresAtMs);
  if (expiresAtMs <= issuedAtMs) fail();
  return Object.freeze({
    schema: RETAINED_LOCAL_ACTION_SCHEMA,
    sessionId: item.sessionId,
    role: role(item.role),
    actionId: item.actionId,
    operation: item.operation,
    requestDigest: digest(item.requestDigest),
    requestLength: item.requestLength,
    commandSha256: digest(item.commandSha256),
    commandLength: item.commandLength,
    policyDigest: digest(item.policyDigest),
    issuedAtMs,
    expiresAtMs,
    adapterRecordDigest: digest(item.adapterRecordDigest),
    adapterSignature: item.adapterSignature,
    adapterPublicKey: item.adapterPublicKey,
  });
}

export function validateHarnessEvent(value) {
  const item = exactObject(value, EVENT_KEYS);
  if (
    item.schema !== HARNESS_EVENT_SCHEMA ||
    item.redacted !== true ||
    typeof item.harness !== "string" ||
    item.harness.length === 0 ||
    !/^(?:0|[1-9][0-9]*)$/.test(item.sequence) ||
    typeof item.sessionId !== "string" ||
    item.sessionId.length === 0 ||
    typeof item.type !== "string" ||
    item.type.length === 0 ||
    typeof item.evidenceRef !== "string" ||
    !item.evidenceRef.startsWith("sha256:")
  ) fail();
  return Object.freeze({
    schema: HARNESS_EVENT_SCHEMA,
    sessionId: item.sessionId,
    role: role(item.role),
    harness: item.harness,
    sequence: item.sequence,
    type: item.type,
    timestampMs: timestamp(item.timestampMs),
    redacted: true,
    publicSummary: safeText(item.publicSummary),
    evidenceRef: `sha256:${digest(item.evidenceRef.slice("sha256:".length))}`,
  });
}

export function createLocalHarnessAdapter(options = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) fail();
  rejectAuthorityFields(options);
  const { harness = "local", retainedActions = [] } = options;
  if (!Array.isArray(retainedActions)) fail();
  const cleanRetainedActions = Object.freeze(retainedActions.map(validateRetainedLocalAction));
  const sessions = new Map();
  return Object.freeze({
    async inspectCapabilities() {
      return Object.freeze({
        schema: "clockchain.harness-capabilities/v1",
        harness,
        retainedLocalActions: true,
        rawPayloadTransport: false,
      });
    },
    async launchSession({ runtime, mandate, mcpEndpoint, a2aConfig }) {
      if (
        runtime === null || typeof runtime !== "object" ||
        mandate === null || typeof mandate !== "object" ||
        typeof mcpEndpoint !== "string" || !mcpEndpoint.startsWith("https://") ||
        a2aConfig === null || typeof a2aConfig !== "object"
      ) fail();
      const sessionId = UUIDISH.test(runtime.sessionId ?? "") ? runtime.sessionId : randomUUID();
      sessions.set(sessionId, {
        role: runtime.role,
        retainedActions: cleanRetainedActions,
        terminated: false,
      });
      return Object.freeze({ sessionId });
    },
    async decideLocalAction({ retainedAction }) {
      return Object.freeze({ decision: "authorize", retainedAction: validateRetainedLocalAction(retainedAction) });
    },
    async executeRetainedAction({ sessionId, role: actionRole, actionId }) {
      const session = sessions.get(sessionId);
      if (session === undefined || !ROLES.includes(actionRole) || typeof actionId !== "string" || actionId.length === 0) fail();
      return Object.freeze({ sessionId, role: actionRole, actionId, executed: true });
    },
    async streamEvents({ sessionId }) {
      if (!sessions.has(sessionId)) fail();
      return Object.freeze([]);
    },
    async terminateSession({ sessionId }) {
      const session = sessions.get(sessionId);
      if (session === undefined) fail();
      sessions.set(sessionId, { ...session, terminated: true });
      return Object.freeze({ sessionId, terminated: true });
    },
    async collectEvidence({ sessionId }) {
      const session = sessions.get(sessionId);
      if (session === undefined) fail();
      if (session.terminated !== true) fail();
      return Object.freeze({
        schema: "clockchain.harness-evidence/v1",
        sessionId,
        teardown: Object.freeze({ completed: session.terminated === true }),
        retainedActions: Object.freeze([...session.retainedActions]),
      });
    },
  });
}
