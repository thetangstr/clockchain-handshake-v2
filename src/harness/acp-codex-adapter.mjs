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
const OPTIONS_KEYS = Object.freeze([
  "decisionCallback", "harness", "nowMs", "pin", "processFactory", "retainedActions",
  "transport", "trustedAdapterPublicKeys",
]);
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
    const descriptors = Object.getOwnPropertyDescriptors(value);
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) fail();
      rejectAuthorityFields(descriptor.value);
    }
    return;
  }
  if (typeof value !== "object") return;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!descriptor.enumerable) continue;
    if (!Object.hasOwn(descriptor, "value")) fail();
    if (/(?:private.?key|secret.?key|controller.?private.?key|signer|override|control)/i.test(key)) fail();
    rejectAuthorityFields(descriptor.value);
  }
}

function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const objectKeys = Object.keys(descriptors);
  if (JSON.stringify(objectKeys.sort()) !== JSON.stringify([...keys].sort())) fail();
  for (const key of objectKeys) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
  }
  return value;
}

function objectValues(value, keys) {
  const item = exactObject(value, keys);
  const descriptors = Object.getOwnPropertyDescriptors(item);
  const result = {};
  for (const key of keys) result[key] = descriptors[key].value;
  return result;
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
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors);
  if (!keys.includes("endpoint") || !keys.includes("peerCard") || keys.some((key) => !["endpoint", "peerCard", "invitationPath"].includes(key))) fail();
  const item = objectValues(value, keys);
  if (typeof item.endpoint !== "string" || !item.endpoint.startsWith("https://")) fail();
  const peerCard = objectValues(item.peerCard, ["endpoint", "id"]);
  if (
    typeof peerCard.id !== "string" || peerCard.id.length === 0 ||
    typeof peerCard.endpoint !== "string" || !peerCard.endpoint.startsWith("https://")
  ) fail();
  if (item.invitationPath !== undefined && (typeof item.invitationPath !== "string" || item.invitationPath.length === 0)) fail();
  return Object.freeze({
    endpoint: item.endpoint,
    peerCard: Object.freeze({ id: peerCard.id, endpoint: peerCard.endpoint }),
    ...(item.invitationPath === undefined ? {} : { invitationPath: item.invitationPath }),
  });
}

function validateRuntime(runtime, expectedHarness) {
  const item = objectValues(runtime, ["harness", "role", "runtimeId", "sessionId"]);
  if (
    typeof item.runtimeId !== "string" || item.runtimeId.length === 0 ||
    typeof item.sessionId !== "string" || item.sessionId.length === 0 ||
    item.harness !== expectedHarness
  ) fail();
  return Object.freeze({
    runtimeId: item.runtimeId,
    sessionId: item.sessionId,
    role: role(item.role),
    harness: expectedHarness,
  });
}

function validateEvidence(value, sessionId, harness, sessionRole) {
  const item = objectValues(value, EVIDENCE_KEYS);
  const teardown = objectValues(item.teardown, ["completed"]);
  const usage = objectValues(item.usage, ["inputTokens", "outputTokens"]);
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
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Object.keys(descriptors).filter((key) => key !== "length");
    if (keys.length !== value.length) fail();
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (descriptor === undefined || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
      result.push(freezeData(descriptor.value, depth + 1));
    }
    return Object.freeze(result);
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
  const item = objectValues(pin, PIN_KEYS);
  const accepted = Object.values(ACP_VERSION_PINS).find((candidate) => (
    candidate.executableName === item.executableName &&
    candidate.integrity === item.integrity &&
    candidate.packageName === item.packageName &&
    candidate.version === item.version
  ));
  if (!accepted) fail();
  return Object.freeze({ ...accepted });
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
  const descriptors = Object.getOwnPropertyDescriptors(options);
  const optionKeys = Object.keys(descriptors);
  for (const key of optionKeys) {
    if (!OPTIONS_KEYS.includes(key)) fail();
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
  }
  rejectAuthorityFields(options);
  const decisionCallback = descriptors.decisionCallback?.value ?? null;
  const harness = descriptors.harness?.value;
  const nowMs = descriptors.nowMs?.value ?? (() => Date.now());
  const pin = descriptors.pin?.value;
  const processFactory = descriptors.processFactory?.value ?? null;
  const retainedActions = descriptors.retainedActions?.value ?? [];
  const transport = descriptors.transport?.value;
  const trustedAdapterPublicKeys = descriptors.trustedAdapterPublicKeys?.value;
  if (processFactory !== null && typeof processFactory !== "function") fail();
  const cleanTransport = snapshotTransport(transport);
  const cleanPin = publicPin(pin);
  if (
    cleanPin.packageName === ACP_VERSION_PINS.codex.packageName && harness !== "codex" ||
    cleanPin.packageName === ACP_VERSION_PINS.claude.packageName && harness !== "claude"
  ) fail();
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
    if (child === null || typeof child !== "object" || Array.isArray(child)) fail();
    const descriptor = Object.getOwnPropertyDescriptor(child, "launch");
    if (descriptor === undefined || !Object.hasOwn(descriptor, "value") || typeof descriptor.value !== "function") fail();
    return descriptor.value.call(child, args);
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
      const cleanArgs = objectValues(args, ["actionId", "role", "sessionId"]);
      if (
        typeof cleanArgs.sessionId !== "string" || cleanArgs.sessionId.length === 0 ||
        typeof cleanArgs.actionId !== "string" || cleanArgs.actionId.length === 0
      ) fail();
      const sanitized = Object.freeze({
        sessionId: cleanArgs.sessionId,
        role: role(cleanArgs.role),
        actionId: cleanArgs.actionId,
      });
      const result = await local.executeRetainedAction(sanitized);
      if (cleanTransport.executeRetainedAction !== undefined) await cleanTransport.executeRetainedAction(sanitized);
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

export function createPinnedAcpHarnessAdapter(options, harness, pin) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(options);
  const result = {};
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (key === "harness" || key === "pin") fail();
    if (!OPTIONS_KEYS.includes(key)) fail();
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    result[key] = descriptor.value;
  }
  result.harness = harness;
  result.pin = pin;
  return createAcpHarnessAdapter(result);
}

export function createAcpCodexHarnessAdapter(options = {}) {
  return createPinnedAcpHarnessAdapter(options, "codex", ACP_VERSION_PINS.codex);
}
