import { createHash, createPublicKey, randomUUID, verify } from "node:crypto";

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
const ACTION_BODY_KEYS = Object.freeze([
  "schema", "sessionId", "role", "actionId", "operation", "requestDigest", "requestLength",
  "commandSha256", "commandLength", "policyDigest", "issuedAtMs", "expiresAtMs",
]);
const EVENT_KEYS = Object.freeze([
  "evidenceRef", "harness", "publicSummary", "redacted", "role", "schema", "sequence",
  "sessionId", "timestampMs", "type",
]);
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

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

function bodyBytes(item) {
  const body = {};
  for (const key of ACTION_BODY_KEYS) body[key] = item[key];
  return Buffer.from(JSON.stringify(body), "utf8");
}

function publicKeyFromRaw(value) {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(value, "base64")]), format: "der", type: "spki" });
}

function rawPublicKey(value) {
  if (typeof value !== "string" || !BASE64.test(value) || Buffer.from(value, "base64").length !== 32) fail();
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
  const bytes = bodyBytes(item);
  const adapterRecordDigest = digest(item.adapterRecordDigest);
  if (createHash("sha256").update(bytes).digest("hex") !== adapterRecordDigest) fail();
  let accepted = false;
  try {
    accepted = verify(null, bytes, publicKeyFromRaw(item.adapterPublicKey), Buffer.from(item.adapterSignature, "base64"));
  } catch {
    accepted = false;
  }
  if (!accepted) fail();
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
    adapterRecordDigest,
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
  const {
    decisionCallback = null,
    harness = "local",
    nowMs = () => Date.now(),
    retainedActions = [],
    trustedAdapterPublicKeys,
  } = options;
  if (!Array.isArray(retainedActions)) fail();
  if (!Array.isArray(trustedAdapterPublicKeys) || trustedAdapterPublicKeys.length < 1) fail();
  if (typeof harness !== "string" || harness.length === 0) fail();
  if (typeof nowMs !== "function") fail();
  if (decisionCallback !== null && typeof decisionCallback !== "function") fail();
  const trustedKeys = new Set(trustedAdapterPublicKeys.map(rawPublicKey));
  if (trustedKeys.size !== trustedAdapterPublicKeys.length) fail();
  const cleanRetainedActions = Object.freeze(retainedActions.map(validateRetainedLocalAction));
  for (const action of cleanRetainedActions) {
    if (!trustedKeys.has(action.adapterPublicKey)) fail();
  }
  const sessions = new Map();
  function now() {
    const value = nowMs();
    if (!Number.isSafeInteger(value) || value < 0) fail();
    return value;
  }
  function retained(sessionId, actionRole, actionId, allowedStates = ["pending"]) {
    const session = sessions.get(sessionId);
    if (session === undefined || session.role !== actionRole) fail();
    const entry = session.retainedActions.get(actionId);
    if (entry === undefined || entry.action.role !== actionRole || entry.action.sessionId !== sessionId) fail();
    if (!allowedStates.includes(entry.state)) fail();
    if (now() > entry.action.expiresAtMs) fail();
    return { session, entry };
  }
  function sameAction(left, right) {
    return JSON.stringify(left) === JSON.stringify(right);
  }
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
      const sessionRole = role(runtime.role);
      const indexed = new Map();
      for (const action of cleanRetainedActions) {
        if (action.sessionId !== sessionId || action.role !== sessionRole) continue;
        if (indexed.has(action.actionId)) fail();
        indexed.set(action.actionId, { action, state: "pending" });
      }
      sessions.set(sessionId, {
        role: sessionRole,
        retainedActions: indexed,
        terminated: false,
      });
      return Object.freeze({ sessionId });
    },
    async decideLocalAction(args) {
      const item = exactObject(args, ["sessionId", "role", "retainedAction"]);
      const suppliedAction = validateRetainedLocalAction(item.retainedAction);
      const { entry } = retained(item.sessionId, role(item.role), suppliedAction.actionId);
      if (!sameAction(suppliedAction, entry.action)) fail();
      if (decisionCallback === null) fail();
      const decision = decisionCallback({ sessionId: item.sessionId, role: item.role, retainedAction: entry.action });
      if (exactObject(decision, ["decision"]).decision !== "authorize") fail();
      entry.state = "authorized";
      return Object.freeze({ decision: "authorize", retainedAction: entry.action });
    },
    async executeRetainedAction({ sessionId, role: actionRole, actionId }) {
      const { entry } = retained(sessionId, role(actionRole), actionId, ["authorized"]);
      entry.state = "consumed";
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
        retainedActions: Object.freeze([...session.retainedActions.values()].map((entry) => entry.action)),
      });
    },
  });
}
