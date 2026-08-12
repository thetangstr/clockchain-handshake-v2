import { createHash } from "node:crypto";
import { spawn as nodeSpawn } from "node:child_process";
import { isAbsolute } from "node:path";
import { Readable, Writable } from "node:stream";
import { types } from "node:util";

import { ClientSideConnection, PROTOCOL_VERSION, ndJsonStream } from "@agentclientprotocol/sdk";

import { validateHarnessEvent, validateRetainedLocalAction } from "./harness-adapter-contract.mjs";
import { ACP_VERSION_PINS } from "./version-pins.mjs";

const MCP_ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
const OPTION_KEYS = Object.freeze([
  "env", "harness", "home", "nowMs", "pin", "retainedActions", "sessionEvidence",
  "spawn", "trustedAdapterPublicKeys", "workspace",
]);
const ROLES = Object.freeze(["initiator", "responder"]);
const MAX_DEPTH = 12;
const MAX_KEYS = 64;
const MAX_ARRAY = 64;
const MAX_STRING = 4096;

function fail() {
  throw new Error("ACP process transport validation failed safely.");
}

function digest(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function digestJson(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail();
  let descriptors;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    fail();
  }
  const actual = Reflect.ownKeys(descriptors);
  if (actual.some((key) => typeof key !== "string")) fail();
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) fail();
  const result = {};
  for (const key of actual) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    result[key] = descriptor.value;
  }
  return result;
}

function optionalObject(value, requiredKeys, optionalKeys) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail();
  const allowed = [...requiredKeys, ...optionalKeys];
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const item = exactObject(value, allowed.filter((key) => {
    return requiredKeys.includes(key) || Object.hasOwn(descriptors, key);
  }));
  return item;
}

function envObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result = {};
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string") fail();
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value") || typeof descriptor.value !== "string") fail();
    result[key] = descriptor.value;
  }
  return result;
}

function rejectAuthority(value) {
  if (value === null || value === undefined || typeof value !== "object") return;
  if (types.isProxy(value)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!descriptor.enumerable) continue;
    if (!Object.hasOwn(descriptor, "value")) fail();
    if (/(?:private.?key|secret.?key|signer|transcript|reasoning|control)/i.test(key)) fail();
    rejectAuthority(descriptor.value);
  }
}

function cleanPublicData(value, depth = 0) {
  if (depth > MAX_DEPTH) fail();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.length > MAX_STRING) fail();
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail();
    return value;
  }
  if (typeof value !== "object" || types.isProxy(value)) fail();
  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (!keys.includes("length")) fail();
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
    }
    if (keys.some((key) => key !== "length" && !/^(?:0|[1-9][0-9]*)$/.test(String(key)))) fail();
    return Object.freeze(Array.from({ length: value.length }, (_, index) => cleanPublicData(descriptors[String(index)].value, depth + 1)));
  }
  if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  rejectAuthority(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length > MAX_KEYS || keys.some((key) => typeof key !== "string")) fail();
  const result = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    result[key] = cleanPublicData(descriptor.value, depth + 1);
  }
  return Object.freeze(result);
}

function cleanOptions(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail();
  let descriptors;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    fail();
  }
  const result = {};
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string") fail();
    const descriptor = descriptors[key];
    if (!OPTION_KEYS.includes(key) || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    result[key] = descriptor.value;
  }
  rejectAuthority(result.sessionEvidence);
  return result;
}

function cleanPin(value, harness) {
  const item = exactObject(value, ["executableName", "integrity", "packageName", "version"]);
  const expected = ACP_VERSION_PINS[harness];
  if (
    expected === undefined ||
    item.executableName !== expected.executableName ||
    item.integrity !== expected.integrity ||
    item.packageName !== expected.packageName ||
    item.version !== expected.version
  ) fail();
  return Object.freeze({ ...expected });
}

function cleanRuntime(value, harness) {
  const item = exactObject(value, ["harness", "role", "runtimeId", "sessionId"]);
  if (item.harness !== harness || !ROLES.includes(item.role)) fail();
  for (const key of ["runtimeId", "sessionId"]) {
    if (typeof item[key] !== "string" || item[key].length === 0) fail();
  }
  return Object.freeze({ ...item });
}

function cleanRetainedActions(value) {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value)) fail();
  return Object.freeze(value.map(validateRetainedLocalAction));
}

function cleanA2A(value) {
  const item = exactObject(value, ["endpoint", "peerCard"]);
  const peer = exactObject(item.peerCard, ["endpoint", "id"]);
  if (typeof item.endpoint !== "string" || !item.endpoint.startsWith("https://")) fail();
  if (typeof peer.endpoint !== "string" || !peer.endpoint.startsWith("https://") || typeof peer.id !== "string" || peer.id.length === 0) fail();
  return Object.freeze({ endpoint: item.endpoint, peerCard: Object.freeze({ ...peer }) });
}

function streamPair(child) {
  try {
    if (child?.stdout?.getReader && child?.stdin?.getWriter) {
      return ndJsonStream(child.stdin, child.stdout);
    }
    if (child?.stdout !== undefined && child?.stdin !== undefined) {
      return ndJsonStream(Writable.toWeb(child.stdin), Readable.toWeb(child.stdout));
    }
  } catch {
    fail();
  }
  fail();
}

function mcpServer() {
  return Object.freeze({
    type: "http",
    name: "clockchain-handshake",
    url: MCP_ENDPOINT,
    headers: Object.freeze([]),
  });
}

function promptText({ role, sessionId, mandate, a2aConfig }) {
  const mandateJson = JSON.stringify(mandate);
  return [
    "Clockchain mechanics proof mandate.",
    `role: ${role}`,
    `session: ${sessionId}`,
    `mandate: ${mandateJson}`,
    `direct A2A endpoint: ${a2aConfig.endpoint}`,
    `direct A2A peer card: ${a2aConfig.peerCard.id}`,
    `direct A2A peer endpoint: ${a2aConfig.peerCard.endpoint}`,
    "Use the dedicated clockchain-handshake MCP server and retained local-action approvals only.",
  ].join("\n");
}

function safeUsage(value) {
  if (value === null || value === undefined) return Object.freeze({ inputTokens: "0", outputTokens: "0" });
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const input = descriptors.inputTokens?.value ?? 0;
  const output = descriptors.outputTokens?.value ?? 0;
  if (!Number.isSafeInteger(input) || input < 0 || !Number.isSafeInteger(output) || output < 0) fail();
  return Object.freeze({ inputTokens: String(input), outputTokens: String(output) });
}

function retainedCommand(value) {
  if (typeof value !== "string" || !/^clockchain-agent-authorize [0-9a-f]{64}$/.test(value)) fail();
  return value.slice("clockchain-agent-authorize ".length);
}

function trustedKeySet(value) {
  if (!Array.isArray(value) || value.length < 1) fail();
  const keys = new Set();
  for (const key of value) {
    if (typeof key !== "string" || key.length === 0) fail();
    keys.add(key);
  }
  if (keys.size !== value.length) fail();
  return keys;
}

export function createAcpProcessTransport(optionsInput = {}) {
  const options = cleanOptions(optionsInput);
  const harness = options.harness;
  if (!["codex", "claude"].includes(harness)) fail();
  const pin = cleanPin(options.pin, harness);
  const spawn = options.spawn ?? nodeSpawn;
  if (typeof spawn !== "function") fail();
  for (const key of ["workspace", "home"]) {
    if (typeof options[key] !== "string" || options[key].length === 0) fail();
  }
  if (!isAbsolute(options.workspace) || !isAbsolute(options.home)) fail();
  const baseEnv = envObject(options.env ?? {});
  const retainedActions = cleanRetainedActions(options.retainedActions);
  const trustedKeys = trustedKeySet(options.trustedAdapterPublicKeys);
  for (const action of retainedActions) {
    if (!trustedKeys.has(action.adapterPublicKey)) fail();
  }
  const nowMs = options.nowMs ?? (() => Date.now());
  if (typeof nowMs !== "function") fail();
  function now() {
    const value = nowMs();
    if (!Number.isSafeInteger(value) || value < 0) fail();
    return value;
  }
  let session = null;
  let acpSessionId = null;
  let child = null;
  let connection = null;
  let completed = false;
  let terminated = false;
  let permissionDenied = false;
  let protocolFailure = false;
  let usage = Object.freeze({ inputTokens: "0", outputTokens: "0" });
  const events = [];
  const retainedByCommand = new Map();
  let sequence = 0;
  function event(type, publicSummary, ref) {
    sequence += 1;
    const timestampMs = now();
    const record = validateHarnessEvent({
      schema: "clockchain.harness-event/v1",
      sessionId: session.sessionId,
      role: session.role,
      harness,
      sequence: String(sequence),
      type,
      timestampMs,
      redacted: true,
      publicSummary,
      evidenceRef: `sha256:${digest(ref)}`,
    });
    events.push(record);
    return record;
  }
  function registerRetainedAction(candidate) {
    const action = validateRetainedLocalAction(candidate);
    if (session === null || action.sessionId !== session.sessionId || action.role !== session.role) fail();
    if (!trustedKeys.has(action.adapterPublicKey)) fail();
    if (now() > action.expiresAtMs) fail();
    if (retainedByCommand.has(action.commandSha256)) fail();
    retainedByCommand.set(action.commandSha256, { action, state: "pending" });
    event("acp.retained_action.registered", "registered retained local action", action.commandSha256);
    return action;
  }
  function permissionCommand(params) {
    const toolCall = params?.toolCall;
    if (toolCall === null || typeof toolCall !== "object" || Array.isArray(toolCall) || types.isProxy(toolCall)) fail();
    const rawInput = exactObject(toolCall.rawInput, ["command"]);
    return retainedCommand(rawInput.command);
  }
  async function requestPermission(params) {
    try {
      if (session === null || params?.sessionId !== acpSessionId) fail();
      const digestValue = permissionCommand(params);
      const entry = retainedByCommand.get(digestValue);
      if (entry === undefined || entry.state !== "pending") fail();
      const optionsList = params?.options;
      if (!Array.isArray(optionsList) || !optionsList.some((option) => option?.optionId === "allow_once" && option?.kind === "allow_once")) fail();
      entry.state = "authorized";
      event("acp.permission.authorized", "authorized retained local action", digestValue);
      return Object.freeze({ outcome: Object.freeze({ outcome: "selected", optionId: "allow_once" }) });
    } catch {
      permissionDenied = true;
      return Object.freeze({ outcome: Object.freeze({ outcome: "cancelled" }) });
    }
  }
  function sessionUpdate(params) {
    try {
      if (session === null || params?.sessionId !== acpSessionId) fail();
      const updateType = params?.update?.sessionUpdate;
      if (typeof updateType !== "string") fail();
      if (updateType === "usage_update") {
        const used = params.update.used;
        if (Number.isSafeInteger(used) && used >= 0) {
          usage = Object.freeze({ inputTokens: String(used), outputTokens: usage.outputTokens });
        }
      }
      if (updateType === "tool_call_update" && params.update.status === "completed" && /^agent_handshake_/.test(params.update.name ?? "")) {
        const output = exactObject(params.update.rawOutput, ["helperStep"]);
        const helperStep = exactObject(output.helperStep, ["action", "invitation", "roleAccess"]);
        registerRetainedAction(helperStep.action);
      }
      event(`acp.${updateType}`, `observed ACP ${updateType}`, digestJson({
        updateType,
        toolCallId: typeof params.update.toolCallId === "string" ? params.update.toolCallId : null,
        status: typeof params.update.status === "string" ? params.update.status : null,
        name: typeof params.update.name === "string" ? params.update.name : null,
      }));
    } catch {
      protocolFailure = true;
    }
  }
  return Object.freeze({
    async launch(input) {
      const launchOptions = exactObject(input, ["a2aConfig", "acp", "mandate", "mcpEndpoint", "runtime"]);
      const { acp, runtime, mandate, mcpEndpoint, a2aConfig } = launchOptions;
      cleanPin(acp, harness);
      const cleanMandate = cleanPublicData(mandate);
      if (mcpEndpoint !== MCP_ENDPOINT) fail();
      const clean = cleanRuntime(runtime, harness);
      const cleanPeer = cleanA2A(a2aConfig);
      session = { sessionId: clean.sessionId, role: clean.role };
      retainedByCommand.clear();
      for (const action of retainedActions) {
        if (action.sessionId === clean.sessionId && action.role === clean.role) registerRetainedAction(action);
      }
      const env = {
        NODE_ENV: "production",
        HOME: options.home,
        XDG_CACHE_HOME: `${options.home}/.cache`,
        CLOCKCHAIN_MCP_URL: MCP_ENDPOINT,
        ...(baseEnv.HTTP_PROXY ? { HTTP_PROXY: baseEnv.HTTP_PROXY } : {}),
        ...(baseEnv.HTTPS_PROXY ? { HTTPS_PROXY: baseEnv.HTTPS_PROXY } : {}),
        NODE_USE_ENV_PROXY: "1",
      };
      child = spawn(pin.executableName, [], {
        cwd: options.workspace,
        env,
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      });
      connection = new ClientSideConnection(() => ({
        requestPermission,
        sessionUpdate,
      }), streamPair(child));
      event("acp.process.launch", `launched ${harness} ACP process`, `${pin.packageName}:${pin.version}:${cleanPeer.peerCard.id}`);
      const initialized = await connection.initialize({
        protocolVersion: PROTOCOL_VERSION,
        clientCapabilities: Object.freeze({}),
      });
      if (initialized?.protocolVersion !== PROTOCOL_VERSION) fail();
      event("acp.initialize", "negotiated ACP protocol", String(initialized.protocolVersion));
      const created = await connection.newSession({
        cwd: options.workspace,
        mcpServers: [mcpServer()],
      });
      if (typeof created?.sessionId !== "string" || created.sessionId.length === 0) fail();
      acpSessionId = created.sessionId;
      event("acp.session.new", "created ACP session", digest(created.sessionId));
      const prompted = await connection.prompt({
        sessionId: acpSessionId,
        prompt: [{
          type: "text",
          text: promptText({ role: clean.role, sessionId: clean.sessionId, mandate: cleanMandate, a2aConfig: cleanPeer }),
        }],
      });
      if (protocolFailure || permissionDenied || prompted?.stopReason !== "end_turn") fail();
      usage = safeUsage(prompted.usage);
      completed = true;
      event("acp.prompt.end_turn", "ACP prompt completed end_turn", digestJson(usage));
      return Object.freeze({ sessionId: clean.sessionId, role: clean.role, harness });
    },
    async executeRetainedAction(input) {
      const { sessionId, role, actionId } = exactObject(input, ["actionId", "role", "sessionId"]);
      if (session === null || session.sessionId !== sessionId || session.role !== role || typeof actionId !== "string" || actionId.length === 0) fail();
      const entry = [...retainedByCommand.values()].find((candidate) => candidate.action.actionId === actionId);
      if (entry === undefined || entry.state !== "authorized") fail();
      entry.state = "consumed";
      return Object.freeze({ executed: true, actionId, sessionId, role });
    },
    async streamEvents(input) {
      const { sessionId } = exactObject(input, ["sessionId"]);
      if (session === null || session.sessionId !== sessionId) fail();
      return Object.freeze(events.map((event) => Object.freeze({ ...event })));
    },
    async terminate(input) {
      const { sessionId, reason = "terminated" } = optionalObject(input, ["sessionId"], ["reason"]);
      if (session === null || session.sessionId !== sessionId || typeof reason !== "string") fail();
      child?.kill?.("SIGTERM");
      if (child?.closed !== undefined) await child.closed;
      terminated = true;
      return Object.freeze({ terminated: true });
    },
    async collectEvidence(input) {
      const { sessionId } = exactObject(input, ["sessionId"]);
      if (session === null || session.sessionId !== sessionId) fail();
      if (completed !== true || terminated !== true) fail();
      const evidence = Object.freeze({
        schema: "clockchain.harness-evidence/v1",
        sessionId,
        harness,
        role: session.role,
        terminalStatus: "completed",
        usage,
        teardown: Object.freeze({ completed: true }),
      });
      if (/cc_secret|CLOCKCHAIN_MCP_BEARER|transcript|reasoning|\/workspace/i.test(JSON.stringify(evidence))) fail();
      return evidence;
    },
  });
}
