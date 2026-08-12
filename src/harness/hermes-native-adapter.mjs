import { types } from "node:util";

import {
  createLocalHarnessAdapter,
  validateHarnessEvent,
} from "./harness-adapter-contract.mjs";
import { buildHermesPrompt } from "../core/hermes-launcher.mjs";

const MCP_ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
const KIT_URL = "https://github.com/thetangstr/clockchain-handshake-v2.git";
const ROLES = Object.freeze(["initiator", "responder"]);
const TOOLS = Object.freeze([
  "agent_handshake_invite",
  "agent_handshake_accept_invitation",
  "agent_handshake_join",
  "agent_handshake_status",
  "agent_handshake_next",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);
const EVIDENCE_KEYS = Object.freeze([
  "harness", "role", "schema", "sessionId", "teardown", "terminalStatus", "usage",
]);
const OPTIONS_KEYS = Object.freeze([
  "decisionCallback", "invitationId", "kitCommit", "kitUrl", "nowMs", "retainedActions",
  "transport", "trustedAdapterPublicKeys",
]);
const TRANSPORT_METHODS = Object.freeze(["collectEvidence", "executeRetainedAction", "launch", "streamEvents", "terminate"]);
const MAX_DATA_DEPTH = 8;
const MAX_ARRAY_LENGTH = 32;
const MAX_OBJECT_KEYS = 64;
const MAX_STRING_LENGTH = 4096;

function fail() {
  throw new Error("Hermes native harness adapter validation failed safely.");
}

function assertNotProxy(value) {
  if (value !== null && (typeof value === "object" || typeof value === "function") && types.isProxy(value)) fail();
}

function smuggledKey(key) {
  const lower = key.toLowerCase();
  return (
    lower === "transcript" ||
    lower === "reasoning" ||
    lower === "path" ||
    lower === "filepath" ||
    lower === "file" ||
    lower === "filename" ||
    lower === "home" ||
    lower === "homedir" ||
    lower === "cwd" ||
    lower.endsWith("path") ||
    lower.endsWith("file") ||
    lower.endsWith("home") ||
    lower.endsWith("cwd") ||
    lower.includes("_path") ||
    lower.includes("_file") ||
    lower.includes("_home") ||
    lower.includes("_cwd") ||
    lower.includes("-path") ||
    lower.includes("-file") ||
    lower.includes("-home") ||
    lower.includes("-cwd")
  );
}

function localPathString(value) {
  return /^(?:\/|~\/|[A-Za-z]:[\\/])/.test(value);
}

function rejectAuthorityFields(value) {
  if (value === null || value === undefined) return;
  assertNotProxy(value);
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
    if (/(?:private.?key|secret.?key|controller.?private.?key|signer|override|control|token|credential)/i.test(key)) fail();
    if (smuggledKey(key)) fail();
    rejectAuthorityFields(descriptor.value);
  }
}

function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  assertNotProxy(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const objectKeys = Object.keys(descriptors);
  if (JSON.stringify(objectKeys.sort()) !== JSON.stringify([...keys].sort())) fail();
  for (const key of objectKeys) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
  }
  return descriptors;
}

function objectValues(value, keys) {
  const descriptors = exactObject(value, keys);
  return Object.fromEntries(keys.map((key) => [key, descriptors[key].value]));
}

function role(value) {
  if (!ROLES.includes(value)) fail();
  return value;
}

function legacyRole(value) {
  return role(value) === "initiator" ? "payer" : "requestor";
}

function isPlainDataObject(value) {
  assertNotProxy(value);
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function freezeData(value, depth = 0) {
  assertNotProxy(value);
  if (depth > MAX_DATA_DEPTH) fail();
  if (typeof value === "string") {
    if (value.length > MAX_STRING_LENGTH) fail();
    if (localPathString(value)) fail();
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

function a2aConfig(value) {
  const item = objectValues(value, ["endpoint", "peerCard"]);
  if (typeof item.endpoint !== "string" || !item.endpoint.startsWith("https://")) fail();
  const peerCard = objectValues(item.peerCard, ["endpoint", "id"]);
  if (
    typeof peerCard.id !== "string" || peerCard.id.length === 0 ||
    typeof peerCard.endpoint !== "string" || !peerCard.endpoint.startsWith("https://")
  ) fail();
  return Object.freeze({
    endpoint: item.endpoint,
    peerCard: Object.freeze({ id: peerCard.id, endpoint: peerCard.endpoint }),
  });
}

function runtime(value) {
  const item = objectValues(value, ["harness", "role", "runtimeId", "sessionId"]);
  if (
    item.harness !== "hermes" ||
    typeof item.runtimeId !== "string" || item.runtimeId.length === 0 ||
    typeof item.sessionId !== "string" || item.sessionId.length === 0
  ) fail();
  return Object.freeze({
    runtimeId: item.runtimeId,
    sessionId: item.sessionId,
    role: role(item.role),
    harness: "hermes",
  });
}

function validateEvidence(value, sessionId, sessionRole) {
  const item = objectValues(value, EVIDENCE_KEYS);
  const teardown = objectValues(item.teardown, ["completed"]);
  const usage = objectValues(item.usage, ["inputTokens", "outputTokens"]);
  if (
    item.schema !== "clockchain.harness-evidence/v1" ||
    item.sessionId !== sessionId ||
    item.role !== sessionRole ||
    item.harness !== "hermes" ||
    item.terminalStatus !== "completed" ||
    teardown.completed !== true ||
    !/^(?:0|[1-9][0-9]*)$/.test(usage.inputTokens) ||
    !/^(?:0|[1-9][0-9]*)$/.test(usage.outputTokens)
  ) fail();
  return Object.freeze({
    schema: item.schema,
    sessionId,
    harness: "hermes",
    role: sessionRole,
    terminalStatus: "completed",
    usage: Object.freeze({ ...usage }),
    teardown: Object.freeze({ completed: true }),
  });
}

function snapshotTransport(transport) {
  if (transport === null || typeof transport !== "object" || Array.isArray(transport)) fail();
  assertNotProxy(transport);
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

export function createHermesNativeHarnessAdapter(options = {}) {
  assertNotProxy(options);
  const descriptors = Object.getOwnPropertyDescriptors(options);
  const optionKeys = Object.keys(descriptors);
  for (const key of optionKeys) {
    if (!OPTIONS_KEYS.includes(key)) fail();
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
  }
  rejectAuthorityFields(options);
  const decisionCallback = descriptors.decisionCallback?.value ?? null;
  const nowMs = descriptors.nowMs?.value ?? (() => Date.now());
  const retainedActions = descriptors.retainedActions?.value ?? [];
  const trustedAdapterPublicKeys = descriptors.trustedAdapterPublicKeys?.value;
  const cleanTransport = snapshotTransport(descriptors.transport?.value ?? {});
  const kitUrl = descriptors.kitUrl?.value ?? KIT_URL;
  const kitCommit = descriptors.kitCommit?.value;
  if (typeof kitCommit !== "string" || !/^[0-9a-f]{40}$/.test(kitCommit) || /^0{40}$/.test(kitCommit)) fail();
  const configuredInvitationId = descriptors.invitationId?.value;
  const local = createLocalHarnessAdapter({
    decisionCallback,
    harness: "hermes",
    nowMs,
    retainedActions,
    trustedAdapterPublicKeys,
  });
  const sessions = new Map();
  return Object.freeze({
    async inspectCapabilities() {
      return Object.freeze({
        schema: "clockchain.harness-capabilities/v1",
        harness: "hermes",
        retainedLocalActions: true,
        rawPayloadTransport: false,
      });
    },
    async launchSession({ runtime: suppliedRuntime, mandate, mcpEndpoint, a2aConfig: suppliedA2aConfig }) {
      if (mcpEndpoint !== MCP_ENDPOINT) fail();
      const cleanRuntime = runtime(suppliedRuntime);
      const cleanMandate = freezeData(mandate);
      const cleanA2aConfig = a2aConfig(suppliedA2aConfig);
      const invitationId = configuredInvitationId ?? cleanRuntime.sessionId;
      const prompt = buildHermesPrompt({
        role: cleanRuntime.role,
        mcpMode: "dedicated-v2",
        kitUrl,
        kitCommit,
        invitationId,
      });
      if (cleanTransport.launch !== undefined) {
        await cleanTransport.launch(Object.freeze({
          runtime: cleanRuntime,
          mandate: cleanMandate,
          mcpEndpoint,
          a2aConfig: cleanA2aConfig,
          tools: TOOLS,
          publicRole: cleanRuntime.role,
          legacyRole: legacyRole(cleanRuntime.role),
          prompt,
        }));
      }
      const launched = await local.launchSession({
        runtime: cleanRuntime,
        mandate: cleanMandate,
        mcpEndpoint,
        a2aConfig: cleanA2aConfig,
      });
      sessions.set(launched.sessionId, { role: cleanRuntime.role });
      return Object.freeze({ sessionId: launched.sessionId, role: cleanRuntime.role, harness: "hermes" });
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
      return validateEvidence(await cleanTransport.collectEvidence({ sessionId }), sessionId, session.role);
    },
  });
}
