import {
  createLocalHarnessAdapter,
  validateHarnessEvent,
} from "./harness-adapter-contract.mjs";
import { ACP_VERSION_PINS } from "./version-pins.mjs";

const MCP_ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
const ROLES = Object.freeze(["initiator", "responder"]);
const EVIDENCE_KEYS = Object.freeze([
  "harness", "role", "schema", "sessionId", "teardown", "terminalStatus", "usage",
]);
const PIN_KEYS = Object.freeze(["executableName", "integrity", "packageName", "version"]);
const TRANSPORT_METHODS = Object.freeze(["collectEvidence", "executeRetainedAction", "launch", "streamEvents", "terminate"]);
const MAX_DATA_DEPTH = 8;
const MAX_ARRAY_LENGTH = 32;
const MAX_OBJECT_KEYS = 64;
const MAX_STRING_LENGTH = 4096;

function fail() {
  throw new Error("ACP harness adapter validation failed safely.");
}

function rejectAuthorityFields(value) {
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) {
    for (const item of value) rejectAuthorityFields(item);
    return;
  }
  if (typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (/(?:private.?key|secret.?key|controller.?private.?key|signer|override|control)/i.test(key)) fail();
    rejectAuthorityFields(child);
  }
}

function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) fail();
  return value;
}

function isPlainDataObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function role(value) {
  if (!ROLES.includes(value)) fail();
  return value;
}

function a2aConfig(value) {
  const item = exactObject(value, ["endpoint", "peerCard"]);
  if (typeof item.endpoint !== "string" || !item.endpoint.startsWith("https://")) fail();
  const peerCard = exactObject(item.peerCard, ["endpoint", "id"]);
  if (
    typeof peerCard.id !== "string" || peerCard.id.length === 0 ||
    typeof peerCard.endpoint !== "string" || !peerCard.endpoint.startsWith("https://")
  ) fail();
  return Object.freeze({
    endpoint: item.endpoint,
    peerCard: Object.freeze({ id: peerCard.id, endpoint: peerCard.endpoint }),
  });
}

function validateRuntime(runtime, expectedHarness) {
  if (runtime === null || typeof runtime !== "object" || Array.isArray(runtime)) fail();
  if (
    typeof runtime.runtimeId !== "string" || runtime.runtimeId.length === 0 ||
    typeof runtime.sessionId !== "string" || runtime.sessionId.length === 0 ||
    runtime.harness !== expectedHarness
  ) fail();
  return Object.freeze({
    runtimeId: runtime.runtimeId,
    sessionId: runtime.sessionId,
    role: role(runtime.role),
    harness: expectedHarness,
  });
}

function validateEvidence(value, sessionId, harness, sessionRole) {
  const item = exactObject(value, EVIDENCE_KEYS);
  const teardown = exactObject(item.teardown, ["completed"]);
  const usage = exactObject(item.usage, ["inputTokens", "outputTokens"]);
  if (
    item.schema !== "clockchain.harness-evidence/v1" ||
    item.sessionId !== sessionId ||
    item.role !== sessionRole ||
    item.harness !== harness ||
    item.terminalStatus !== "completed" ||
    teardown.completed !== true ||
    !/^(?:0|[1-9][0-9]*)$/.test(usage.inputTokens) ||
    !/^(?:0|[1-9][0-9]*)$/.test(usage.outputTokens)
  ) fail();
  return Object.freeze({
    schema: item.schema,
    sessionId,
    harness,
    role: sessionRole,
    terminalStatus: "completed",
    usage: Object.freeze({ ...usage }),
    teardown: Object.freeze({ completed: true }),
  });
}

function freezePlain(value) {
  return freezeData(value, 0);
}

function freezeData(value, depth) {
  if (depth > MAX_DATA_DEPTH) fail();
  if (typeof value === "string") {
    if (value.length > MAX_STRING_LENGTH) fail();
    return value;
  }
  if (typeof value === "boolean" || value === null) return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail();
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY_LENGTH) fail();
    return Object.freeze(value.map((entry) => freezeData(entry, depth + 1)));
  }
  if (!isPlainDataObject(value)) fail();
  rejectAuthorityFields(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors);
  if (keys.length > MAX_OBJECT_KEYS) fail();
  const result = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    result[key] = freezeData(descriptor.value, depth + 1);
  }
  return Object.freeze(result);
}

function publicPin(pin) {
  const item = exactObject(pin, PIN_KEYS);
  return Object.freeze({ ...item });
}

function snapshotTransport(transport) {
  if (transport === null || typeof transport !== "object" || Array.isArray(transport)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(transport);
  const result = {};
  for (const name of TRANSPORT_METHODS) {
    const descriptor = descriptors[name];
    if (descriptor === undefined) continue;
    if (!Object.hasOwn(descriptor, "value") || typeof descriptor.value !== "function") fail();
    result[name] = descriptor.value.bind(transport);
  }
  return Object.freeze(result);
}

export function createAcpHarnessAdapter(options = {}) {
  rejectAuthorityFields(options);
  const {
    decisionCallback = null,
    harness,
    nowMs = () => Date.now(),
    pin,
    processFactory = null,
    retainedActions = [],
    transport,
    trustedAdapterPublicKeys,
  } = options;
  if (Object.keys(options).some((key) => ![
    "decisionCallback", "harness", "nowMs", "pin", "processFactory", "retainedActions",
    "transport", "trustedAdapterPublicKeys",
  ].includes(key))) fail();
  if (processFactory !== null && typeof processFactory !== "function") fail();
  const cleanTransport = snapshotTransport(transport);
  const cleanPin = publicPin(pin);
  const local = createLocalHarnessAdapter({
    decisionCallback,
    harness,
    nowMs,
    retainedActions,
    trustedAdapterPublicKeys,
  });
  const sessions = new Map();
  async function launchViaTransport(args) {
    if (cleanTransport.launch !== undefined) return cleanTransport.launch(args);
    if (processFactory === null) fail();
    const child = await processFactory({ acp: cleanPin, executableName: cleanPin.executableName });
    if (child === null || typeof child !== "object" || typeof child.launch !== "function") fail();
    return child.launch(args);
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
    async launchSession({ runtime, mandate, mcpEndpoint, a2aConfig: suppliedA2aConfig }) {
      const cleanMandate = freezePlain(mandate);
      if (mcpEndpoint !== MCP_ENDPOINT) fail();
      const cleanRuntime = validateRuntime(runtime, harness);
      const cleanA2aConfig = a2aConfig(suppliedA2aConfig);
      await launchViaTransport({
        acp: cleanPin,
        runtime: cleanRuntime,
        mandate: cleanMandate,
        mcpEndpoint,
        a2aConfig: cleanA2aConfig,
      });
      const launched = await local.launchSession({
        runtime: cleanRuntime,
        mandate: cleanMandate,
        mcpEndpoint,
        a2aConfig: cleanA2aConfig,
      });
      sessions.set(launched.sessionId, { role: cleanRuntime.role });
      return Object.freeze({ sessionId: launched.sessionId, role: cleanRuntime.role, harness });
    },
    decideLocalAction(args) {
      return local.decideLocalAction(args);
    },
    async executeRetainedAction(args) {
      const result = await local.executeRetainedAction(args);
      if (cleanTransport.executeRetainedAction !== undefined) await cleanTransport.executeRetainedAction(args);
      return result;
    },
    async streamEvents({ sessionId, since = null }) {
      if (!sessions.has(sessionId)) fail();
      const events = cleanTransport.streamEvents === undefined ? [] : await cleanTransport.streamEvents({ sessionId, since });
      if (!Array.isArray(events)) fail();
      return Object.freeze(events.map(validateHarnessEvent));
    },
    async terminateSession({ sessionId, reason = "terminated" }) {
      if (!sessions.has(sessionId)) fail();
      if (cleanTransport.terminate !== undefined) await cleanTransport.terminate({ sessionId, reason });
      return local.terminateSession({ sessionId, reason });
    },
    async collectEvidence({ sessionId }) {
      const session = sessions.get(sessionId);
      if (session === undefined) fail();
      if (cleanTransport.collectEvidence === undefined) fail();
      await local.collectEvidence({ sessionId });
      const evidence = validateEvidence(await cleanTransport.collectEvidence({ sessionId }), sessionId, harness, session.role);
      return Object.freeze({ ...evidence, acp: cleanPin });
    },
  });
}

export function createAcpCodexHarnessAdapter(options = {}) {
  return createAcpHarnessAdapter({
    ...options,
    harness: "codex",
    pin: ACP_VERSION_PINS.codex,
  });
}
