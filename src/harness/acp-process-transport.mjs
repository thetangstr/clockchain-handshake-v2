import { createHash } from "node:crypto";
import { spawn as nodeSpawn } from "node:child_process";
import { isAbsolute, relative } from "node:path";
import { Readable, Writable } from "node:stream";
import { types } from "node:util";

import { ClientSideConnection, PROTOCOL_VERSION, ndJsonStream } from "@agentclientprotocol/sdk";

import { validateHarnessEvent, validateRetainedLocalAction } from "./harness-adapter-contract.mjs";
import { ACP_VERSION_PINS } from "./version-pins.mjs";

const MCP_ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
const ACTION_KEYS = Object.freeze([
  "actionId", "adapterPublicKey", "adapterRecordDigest", "adapterSignature", "commandLength",
  "commandSha256", "expiresAtMs", "issuedAtMs", "operation", "policyDigest", "requestDigest",
  "requestLength", "role", "schema", "sessionId",
]);
const OPTION_KEYS = Object.freeze([
  "actionRecorder", "env", "harness", "home", "nowMs", "pin", "retainedActions",
  "partyBridge", "spawn", "trustedAdapterPublicKeys", "workspace",
]);
const TOOL_SERVER = "clockchain-handshake";
const TOOL_PREFIX = "agent_handshake_";
const ROLES = Object.freeze(["initiator", "responder"]);
const MAX_DEPTH = 12;
const MAX_KEYS = 64;
const MAX_ARRAY = 64;
const MAX_STRING = 4096;
const MAX_HELPER_COMMAND = 64 * 1024;
const PROCESS_TERM_GRACE_MS = 50;
const PROCESS_KILL_GRACE_MS = 50;
const CODEX_MODEL = "gpt-5.6-terra";
const CLAUDE_BEDROCK_MODEL = "us.anthropic.claude-sonnet-4-6";
const LAUNCH_FAILURE_STAGES = Object.freeze([
  "spawn", "stream", "initialize", "session", "model", "prompt", "completion",
  "completion-protocol", "completion-protocol-envelope", "completion-protocol-usage",
  "completion-protocol-tool-result", "completion-protocol-bridge", "completion-protocol-retained",
  "completion-protocol-event", "completion-protocol-envelope-runtime", "completion-protocol-envelope-session-id",
  "completion-protocol-envelope-update-type", "completion-protocol-envelope-before-session",
  "completion-protocol-envelope-early-tool", "completion-protocol-envelope-provisional-session",
  "completion-protocol-envelope-active-session", "completion-permission", "completion-stop",
]);
const LAUNCH_FAILURES = new WeakMap();

function fail() {
  throw new Error("ACP process transport validation failed safely.");
}

function stagedLaunchFailure(stage) {
  if (!LAUNCH_FAILURE_STAGES.includes(stage)) fail();
  const error = new Error("ACP process transport validation failed safely.");
  LAUNCH_FAILURES.set(error, stage);
  return error;
}

export function acpProcessTransportFailureStage(error) {
  return LAUNCH_FAILURES.get(error) ?? null;
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

function cleanProviderEnv(baseEnv, harness) {
  const env = {};
  if (harness === "codex") {
    if (
      (baseEnv.CODEX_API_KEY !== undefined || baseEnv.OPENAI_API_KEY !== undefined) &&
      baseEnv.CLOCKCHAIN_CODEX_MODEL !== CODEX_MODEL
    ) fail();
    if (baseEnv.CLOCKCHAIN_CODEX_MODEL !== undefined && baseEnv.CLOCKCHAIN_CODEX_MODEL !== CODEX_MODEL) fail();
    if (baseEnv.CODEX_API_KEY !== undefined && baseEnv.OPENAI_API_KEY !== undefined) fail();
    if (baseEnv.CODEX_API_KEY !== undefined) env.CODEX_API_KEY = nonemptyBoundedString(baseEnv.CODEX_API_KEY, 16 * 1024);
    if (baseEnv.OPENAI_API_KEY !== undefined) env.OPENAI_API_KEY = nonemptyBoundedString(baseEnv.OPENAI_API_KEY, 16 * 1024);
    return Object.freeze({ env: Object.freeze(env), model: CODEX_MODEL });
  }
  if (baseEnv.ANTHROPIC_API_KEY !== undefined || baseEnv.CODEX_API_KEY !== undefined || baseEnv.OPENAI_API_KEY !== undefined) fail();
  const hasBedrockInput = [
    "CLAUDE_CODE_USE_BEDROCK", "ANTHROPIC_MODEL", "AWS_REGION", "AWS_DEFAULT_REGION",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
  ].some((key) => baseEnv[key] !== undefined);
  if (!hasBedrockInput) return Object.freeze({ env: Object.freeze(env), model: CLAUDE_BEDROCK_MODEL });
  if (baseEnv.CLAUDE_CODE_USE_BEDROCK !== "1" || baseEnv.ANTHROPIC_MODEL !== CLAUDE_BEDROCK_MODEL) fail();
  env.CLAUDE_CODE_USE_BEDROCK = "1";
  env.ANTHROPIC_MODEL = CLAUDE_BEDROCK_MODEL;
  for (const key of [
    "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
  ]) {
    if (baseEnv[key] !== undefined) env[key] = nonemptyBoundedString(baseEnv[key], 4096);
  }
  if (env.AWS_REGION === undefined && env.AWS_DEFAULT_REGION === undefined) fail();
  const hasContainerCredentials = env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI !== undefined || env.AWS_CONTAINER_CREDENTIALS_FULL_URI !== undefined;
  const hasWebIdentity = env.AWS_WEB_IDENTITY_TOKEN_FILE !== undefined || env.AWS_ROLE_ARN !== undefined;
  const hasStaticCredentials = env.AWS_ACCESS_KEY_ID !== undefined || env.AWS_SECRET_ACCESS_KEY !== undefined || env.AWS_SESSION_TOKEN !== undefined;
  if ([hasContainerCredentials, hasWebIdentity, hasStaticCredentials].filter(Boolean).length !== 1) fail();
  if (hasWebIdentity && !(env.AWS_WEB_IDENTITY_TOKEN_FILE !== undefined && env.AWS_ROLE_ARN !== undefined)) fail();
  if (hasStaticCredentials && !(env.AWS_ACCESS_KEY_ID !== undefined && env.AWS_SECRET_ACCESS_KEY !== undefined)) fail();
  return Object.freeze({ env: Object.freeze(env), model: CLAUDE_BEDROCK_MODEL });
}

function executablePath(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096) fail();
  const entries = value.split(":");
  if (entries.length < 1 || entries.some((entry) => !isAbsolute(entry) || entry.includes(".."))) fail();
  return value;
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
  return Object.freeze(snapshotArray(value).map((action) => validateRetainedLocalAction(exactObject(action, ACTION_KEYS))));
}

function cleanA2A(value) {
  const item = optionalObject(value, ["endpoint", "peerCard"], ["invitationPath"]);
  const peer = exactObject(item.peerCard, ["endpoint", "id"]);
  if (typeof item.endpoint !== "string" || !item.endpoint.startsWith("https://")) fail();
  if (typeof peer.endpoint !== "string" || !peer.endpoint.startsWith("https://") || typeof peer.id !== "string" || peer.id.length === 0) fail();
  if (item.invitationPath !== undefined && (typeof item.invitationPath !== "string" || !isAbsolute(item.invitationPath))) fail();
  return Object.freeze({
    endpoint: item.endpoint,
    peerCard: Object.freeze({ ...peer }),
    ...(item.invitationPath === undefined ? {} : { invitationPath: item.invitationPath }),
  });
}

function nonemptyBoundedString(value, max = MAX_STRING) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) fail();
  return value;
}

function cleanMandate(value) {
  const item = exactObject(value, ["identityPolicy", "reference", "statement", "validForSeconds"]);
  const policy = exactObject(item.identityPolicy, ["chainId", "erc8004", "registryAddress"]);
  if (!["required_fresh", "required_existing_or_fresh", "not_required"].includes(policy.erc8004)) fail();
  if (policy.erc8004 === "not_required") {
    if (policy.chainId !== null || policy.registryAddress !== null) fail();
  } else {
    if (policy.chainId !== "eip155:11155111") fail();
    if (policy.registryAddress !== "0x8004a818bfb912233c491871b3d84c89a494bd9e") fail();
  }
  if (!/^(?:[1-9]|[1-8][0-9]|90)$/.test(item.validForSeconds)) fail();
  return Object.freeze({
    reference: nonemptyBoundedString(item.reference, 256),
    statement: nonemptyBoundedString(item.statement, 2048),
    validForSeconds: item.validForSeconds,
    identityPolicy: Object.freeze({ ...policy }),
  });
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
    ...(role === "responder" && a2aConfig.invitationPath !== undefined ? [
      `Before your first MCP call, read exactly one UTF-8 invitation from ${a2aConfig.invitationPath}.`,
      "Pass that exact value unchanged to agent_handshake_accept_invitation; do not print, summarize, or copy it anywhere else.",
    ] : []),
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
  const list = snapshotArray(value, { min: 1 });
  const keys = new Set();
  for (const key of list) {
    if (typeof key !== "string" || key.length === 0) fail();
    keys.add(key);
  }
  if (keys.size !== list.length) fail();
  return keys;
}

function snapshotArray(value, { min = 0, max = MAX_ARRAY } = {}) {
  if (typeof value !== "object" || value === null || types.isProxy(value) || !Array.isArray(value)) fail();
  if (value.length < min || value.length > max) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (!keys.includes("length")) fail();
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
  }
  if (keys.some((key) => key !== "length" && !/^(?:0|[1-9][0-9]*)$/.test(String(key)))) fail();
  return Array.from({ length: value.length }, (_, index) => descriptors[String(index)].value);
}

function cleanActionRecorder(value) {
  if (value === undefined) return null;
  const item = exactObject(value, ["record"]);
  if (typeof item.record !== "function") fail();
  return Object.freeze({ record: item.record });
}

function cleanPartyBridge(value) {
  if (value === undefined) return null;
  const item = exactObject(value, ["observeToolResult"]);
  if (typeof item.observeToolResult !== "function") fail();
  return Object.freeze({ observeToolResult: item.observeToolResult });
}

function parseToolName(update) {
  const rawInput = update.rawInput;
  if (rawInput !== undefined) {
    try {
      const input = optionalObject(rawInput, ["server", "tool"], ["arguments"]);
      if (input.server === TOOL_SERVER && typeof input.tool === "string" && input.tool.startsWith(TOOL_PREFIX)) return input.tool;
    } catch {
      // Other ACP tools may have unrelated rawInput shapes.
    }
  }
  const claudeName = update._meta?.claudeCode?.toolName;
  if (typeof claudeName === "string" && claudeName.startsWith(`mcp__${TOOL_SERVER}__${TOOL_PREFIX}`)) {
    return claudeName.slice(`mcp__${TOOL_SERVER}__`.length);
  }
  return null;
}

function cleanHelperStep(value) {
  const item = optionalObject(value, [
    "approvalCommand", "commandLength", "commandSha256", "operation", "role", "sessionId", "shellCommand",
  ], ["policyDigest"]);
  if (
    typeof item.commandSha256 !== "string" || !/^[0-9a-f]{64}$/.test(item.commandSha256) ||
    item.approvalCommand !== `clockchain-agent-authorize ${item.commandSha256}` ||
    !Number.isSafeInteger(item.commandLength) || item.commandLength < 1 ||
    typeof item.operation !== "string" || item.operation.length === 0 ||
    !ROLES.includes(item.role) ||
    typeof item.sessionId !== "string" || item.sessionId.length === 0 ||
    typeof item.shellCommand !== "string" ||
    Buffer.byteLength(item.shellCommand) < 1 ||
    Buffer.byteLength(item.shellCommand) > MAX_HELPER_COMMAND ||
    item.commandLength !== Buffer.byteLength(item.shellCommand) ||
    (item.policyDigest !== undefined && (typeof item.policyDigest !== "string" || !/^[0-9a-f]{64}$/.test(item.policyDigest)))
  ) fail();
  return Object.freeze({
    approvalCommand: item.approvalCommand,
    commandLength: item.commandLength,
    commandSha256: item.commandSha256,
    operation: item.operation,
    ...(item.policyDigest === undefined ? {} : { policyDigest: item.policyDigest }),
    role: item.role,
    sessionId: item.sessionId,
    shellCommand: item.shellCommand,
  });
}

function appendHelperSteps(value, found) {
  if (value === null || value === undefined) return;
  if (typeof value === "string") {
    let parsed;
    try {
      parsed = JSON.parse(value);
    } catch {
      fail();
    }
    appendHelperSteps(parsed, found);
    return;
  }
  if (Array.isArray(value)) {
    const blocks = snapshotArray(value);
    for (const blockValue of blocks) {
      const block = exactObject(blockValue, ["text", "type"]);
      if (block.type !== "text") fail();
      appendHelperSteps(block.text, found);
    }
    return;
  }
  if (typeof value !== "object" || types.isProxy(value)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string")) fail();
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
  }
  const helperStep = descriptors.helperStep?.value;
  if (helperStep !== undefined) {
    found.push(cleanHelperStep(helperStep));
  }
  const helperSteps = descriptors.helperSteps?.value;
  if (helperSteps !== undefined) {
    for (const step of snapshotArray(helperSteps)) found.push(cleanHelperStep(step));
  }
  const localAction = descriptors.localAction?.value;
  if (localAction !== undefined) appendHelperSteps(localAction, found);
  const structuredContent = descriptors.structuredContent?.value;
  if (structuredContent !== undefined) appendHelperSteps(structuredContent, found);
  const content = descriptors.content?.value;
  if (content !== undefined) appendHelperSteps(content, found);
}

function authoritativeToolResult(update) {
  const toolName = parseToolName(update);
  if (toolName === null || update.status !== "completed") return null;
  const rawOutput = update.rawOutput;
  if (rawOutput === undefined) fail();
  let result;
  if (Array.isArray(rawOutput)) {
    result = rawOutput;
  } else {
    const output = exactObject(rawOutput, ["error", "result"]);
    if (output.error !== null && output.error !== undefined) fail();
    result = output.result;
  }
  return Object.freeze({ result, toolName });
}

function retainedActionsFromToolResult(result, actionRecorder) {
  const steps = [];
  appendHelperSteps(result, steps);
  if (steps.length === 0) return [];
  if (steps.length !== 1 || actionRecorder === null) fail();
  const actions = [];
  for (const step of steps) {
    actions.push(validateRetainedLocalAction(actionRecorder.record(step)));
  }
  const unique = new Map(actions.map((action) => [action.commandSha256, action]));
  if (unique.size !== actions.length) fail();
  return actions;
}

function wait(ms) {
  return new Promise((resolve) => { setTimeout(resolve, ms); });
}

function childExited(value, monitor = null) {
  return monitor?.closed === true || (value?.exitCode !== null && value?.exitCode !== undefined);
}

function observeChildProcess(value) {
  const monitor = { closed: false, errored: false, promise: null };
  monitor.promise = new Promise((resolve) => {
    let settled = false;
    const remove = () => {
      value?.off?.("close", finishClosed);
      value?.off?.("exit", finishClosed);
      value?.off?.("error", finishError);
      value?.removeListener?.("close", finishClosed);
      value?.removeListener?.("exit", finishClosed);
      value?.removeListener?.("error", finishError);
    };
    const finishClosed = () => {
      if (settled) return;
      settled = true;
      monitor.closed = true;
      remove();
      resolve(true);
    };
    const finishError = () => {
      monitor.errored = true;
    };
    if (typeof value?.once === "function") {
      value.once("close", finishClosed);
      value.once("exit", finishClosed);
      value.once("error", finishError);
    }
    if (value?.closed !== undefined) {
      Promise.resolve(value.closed).then(finishClosed, finishError);
    }
  });
  return monitor;
}

async function waitForChildExit(value, monitor, timeoutMs) {
  if (childExited(value, monitor)) return true;
  if (monitor?.promise === null || monitor?.promise === undefined) return false;
  const token = Symbol("timeout");
  return await Promise.race([monitor.promise.then(() => true), wait(timeoutMs).then(() => token)]) !== token;
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
  const provider = cleanProviderEnv(baseEnv, harness);
  const retainedActions = cleanRetainedActions(options.retainedActions);
  const trustedKeys = trustedKeySet(options.trustedAdapterPublicKeys);
  const actionRecorder = cleanActionRecorder(options.actionRecorder);
  const partyBridge = cleanPartyBridge(options.partyBridge);
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
  let protocolSessionId = null;
  let acpSessionId = null;
  let provisionalAcpSessionId = null;
  let sessionEstablishing = false;
  let child = null;
  let childMonitor = null;
  let connection = null;
  let completed = false;
  let terminated = false;
  let permissionDenied = false;
  let protocolFailure = false;
  let protocolFailureStage = null;
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
    const expectedSessionId = partyBridge === null ? session?.sessionId : protocolSessionId;
    if (session === null || expectedSessionId === null || action.sessionId !== expectedSessionId || action.role !== session.role) fail();
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
  async function sessionUpdate(params) {
    let failureStage = "envelope-runtime";
    try {
      if (session === null) fail();
      failureStage = "envelope-session-id";
      if (typeof params?.sessionId !== "string" || params.sessionId.length === 0) fail();
      failureStage = "envelope-update-type";
      const updateType = params?.update?.sessionUpdate;
      if (typeof updateType !== "string") fail();
      if (acpSessionId === null) {
        failureStage = "envelope-before-session";
        if (!sessionEstablishing) fail();
        failureStage = "envelope-early-tool";
        if (updateType === "tool_call" || updateType === "tool_call_update") fail();
        failureStage = "envelope-provisional-session";
        if (provisionalAcpSessionId === null) provisionalAcpSessionId = params.sessionId;
        else if (params.sessionId !== provisionalAcpSessionId) fail();
      } else {
        failureStage = "envelope-active-session";
        if (params.sessionId !== acpSessionId) fail();
      }
      if (updateType === "usage_update") {
        failureStage = "usage";
        const used = params.update.used;
        if (Number.isSafeInteger(used) && used >= 0) {
          usage = Object.freeze({ inputTokens: String(used), outputTokens: usage.outputTokens });
        }
      }
      if (updateType === "tool_call" || updateType === "tool_call_update") {
        failureStage = "tool-result";
        const toolResult = authoritativeToolResult(params.update);
        if (toolResult !== null) {
          if (partyBridge !== null) {
            failureStage = "bridge";
            const observed = exactObject(
              await partyBridge.observeToolResult({ toolName: toolResult.toolName, result: toolResult.result }),
              ["observed", "protocolSessionId", "toolResultDigest"],
            );
            if (observed.observed !== true || typeof observed.toolResultDigest !== "string" || !/^[0-9a-f]{64}$/.test(observed.toolResultDigest)) fail();
            if (!(observed.protocolSessionId === null || typeof observed.protocolSessionId === "string" && observed.protocolSessionId.length > 0)) fail();
            if (observed.protocolSessionId !== null) {
              if (protocolSessionId !== null && protocolSessionId !== observed.protocolSessionId) fail();
              protocolSessionId = observed.protocolSessionId;
              for (const action of retainedActions) {
                if (
                  action.sessionId === protocolSessionId && action.role === session.role &&
                  !retainedByCommand.has(action.commandSha256)
                ) registerRetainedAction(action);
              }
            }
          }
          failureStage = "retained";
          for (const retained of retainedActionsFromToolResult(toolResult.result, actionRecorder)) {
            registerRetainedAction(retained);
          }
        }
      }
      failureStage = "event";
      event(`acp.${updateType}`, `observed ACP ${updateType}`, digestJson({
        updateType,
        toolCallId: typeof params.update.toolCallId === "string" ? params.update.toolCallId : null,
        status: typeof params.update.status === "string" ? params.update.status : null,
        name: typeof params.update.name === "string" ? params.update.name : null,
        title: typeof params.update.title === "string" ? params.update.title : null,
      }));
    } catch {
      protocolFailure = true;
      protocolFailureStage ??= failureStage;
    }
  }
  return Object.freeze({
    async launch(input) {
      const launchOptions = exactObject(input, ["a2aConfig", "acp", "mandate", "mcpEndpoint", "runtime"]);
      const { acp, runtime, mandate, mcpEndpoint, a2aConfig } = launchOptions;
      cleanPin(acp, harness);
      const cleanMandateValue = cleanMandate(mandate);
      if (mcpEndpoint !== MCP_ENDPOINT) fail();
      const clean = cleanRuntime(runtime, harness);
      const cleanPeer = cleanA2A(a2aConfig);
      if (cleanPeer.invitationPath !== undefined) {
        if (clean.role !== "responder") fail();
        const offset = relative(options.workspace, cleanPeer.invitationPath);
        if (offset === "" || offset.startsWith("..") || isAbsolute(offset)) fail();
      }
      session = { sessionId: clean.sessionId, role: clean.role };
      protocolSessionId = null;
      acpSessionId = null;
      provisionalAcpSessionId = null;
      sessionEstablishing = false;
      retainedByCommand.clear();
      for (const action of retainedActions) {
        if (partyBridge === null && action.sessionId === clean.sessionId && action.role === clean.role) registerRetainedAction(action);
      }
      const env = {
        NODE_ENV: "production",
        HOME: options.home,
        XDG_CACHE_HOME: `${options.home}/.cache`,
        CLOCKCHAIN_MCP_URL: MCP_ENDPOINT,
        ...provider.env,
        ...(baseEnv.HTTP_PROXY ? { HTTP_PROXY: baseEnv.HTTP_PROXY } : {}),
        ...(baseEnv.HTTPS_PROXY ? { HTTPS_PROXY: baseEnv.HTTPS_PROXY } : {}),
        NODE_USE_ENV_PROXY: "1",
        ...(baseEnv.PATH ? { PATH: executablePath(baseEnv.PATH) } : {}),
      };
      let launchStage = "spawn";
      try {
        child = spawn(pin.executableName, [], {
          cwd: options.workspace,
          env,
          stdio: ["pipe", "pipe", "pipe"],
          windowsHide: true,
        });
        childMonitor = observeChildProcess(child);
        launchStage = "stream";
        connection = new ClientSideConnection(() => ({
          requestPermission,
          sessionUpdate,
        }), streamPair(child));
        event("acp.process.launch", `launched ${harness} ACP process`, `${pin.packageName}:${pin.version}:${cleanPeer.peerCard.id}`);
        launchStage = "initialize";
        const initialized = await connection.initialize({
          protocolVersion: PROTOCOL_VERSION,
          clientCapabilities: Object.freeze({}),
        });
        if (initialized?.protocolVersion !== PROTOCOL_VERSION) fail();
        event("acp.initialize", "negotiated ACP protocol", String(initialized.protocolVersion));
        launchStage = "session";
        sessionEstablishing = true;
        const created = await connection.newSession({
          cwd: options.workspace,
          mcpServers: [mcpServer()],
        });
        sessionEstablishing = false;
        if (typeof created?.sessionId !== "string" || created.sessionId.length === 0) fail();
        if (provisionalAcpSessionId !== null && provisionalAcpSessionId !== created.sessionId) fail();
        acpSessionId = created.sessionId;
        if (harness === "codex") {
          launchStage = "model";
          await connection.setSessionConfigOption({
            sessionId: acpSessionId,
            configId: "model",
            value: provider.model,
          });
          event("acp.model.pinned", "pinned Codex ACP model", "model:gpt-5.6-terra");
        }
        event("acp.session.new", "created ACP session", digest(created.sessionId));
        launchStage = "prompt";
        const prompted = await connection.prompt({
          sessionId: acpSessionId,
          prompt: [{
            type: "text",
            text: promptText({ role: clean.role, sessionId: clean.sessionId, mandate: cleanMandateValue, a2aConfig: cleanPeer }),
          }],
        });
        launchStage = "completion";
        if (protocolFailure) {
          launchStage = `completion-protocol-${protocolFailureStage ?? "envelope"}`;
          fail();
        }
        if (permissionDenied) {
          launchStage = "completion-permission";
          fail();
        }
        if (prompted?.stopReason !== "end_turn") {
          launchStage = "completion-stop";
          fail();
        }
        usage = safeUsage(prompted.usage);
        completed = true;
        event("acp.prompt.end_turn", "ACP prompt completed end_turn", digestJson(usage));
        return Object.freeze({ sessionId: clean.sessionId, role: clean.role, harness });
      } catch {
        try {
          if (!childExited(child, childMonitor) && typeof child?.kill === "function") {
            child.kill("SIGTERM");
            if (!await waitForChildExit(child, childMonitor, PROCESS_TERM_GRACE_MS)) {
              child.kill("SIGKILL");
              await waitForChildExit(child, childMonitor, PROCESS_KILL_GRACE_MS);
            }
          }
        } catch {
          // The public failure remains generic; teardown proof is handled by collectEvidence.
        }
        throw stagedLaunchFailure(launchStage);
      }
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
      if (!childExited(child, childMonitor)) {
        if (typeof child?.kill !== "function") fail();
        child.kill("SIGTERM");
        if (!await waitForChildExit(child, childMonitor, PROCESS_TERM_GRACE_MS)) {
          child.kill("SIGKILL");
          if (!await waitForChildExit(child, childMonitor, PROCESS_KILL_GRACE_MS)) fail();
        }
      }
      if (childMonitor?.errored === true && childMonitor.closed !== true) fail();
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
