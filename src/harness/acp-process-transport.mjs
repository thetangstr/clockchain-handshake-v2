import { createHash } from "node:crypto";
import { spawn as nodeSpawn } from "node:child_process";
import { isAbsolute, relative } from "node:path";
import { Readable, Writable } from "node:stream";
import { types } from "node:util";

import { ClientSideConnection, PROTOCOL_VERSION, ndJsonStream } from "@agentclientprotocol/sdk";

import { validateHarnessEvent, validateRetainedLocalAction } from "./harness-adapter-contract.mjs";
import { directA2APartyBridgeFailureStage } from "./direct-a2a-party-bridge.mjs";
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
const HELPER_OPERATIONS = Object.freeze(["init", "policy", "inspect", "register", "sign", "verify-certificate"]);
const MAX_DEPTH = 12;
const MAX_KEYS = 64;
const MAX_ARRAY = 64;
const MAX_STRING = 4096;
const MAX_HELPER_COMMAND = 64 * 1024;
const MAX_PROVISIONAL_TOOL_UPDATES = 16;
const MAX_COMPLETION_PROMPTS = 16;
const PERMISSION_REGISTRATION_GRACE_MS = 5_000;
const PROCESS_TERM_GRACE_MS = 50;
const PROCESS_KILL_GRACE_MS = 50;
const PERMISSION_COMMAND_FAILURES = new WeakMap();
const PERMISSION_COMMAND_STAGES = Object.freeze(["tool", "input", "cwd", "approval"]);
const PERMISSION_FAILURE_STAGES = Object.freeze([
  "session", "protocol", "registration", "state", "options", "unknown",
  ...PERMISSION_COMMAND_STAGES.flatMap((stage) => [`command-${stage}`, `command-${stage}-after-authorization`]),
]);
const CODEX_MODEL = "gpt-5.6-terra";
const CLAUDE_BEDROCK_MODEL = "us.anthropic.claude-sonnet-4-6";
const LAUNCH_FAILURE_STAGES = Object.freeze([
  "spawn", "stream", "initialize", "session", "model", "prompt", "completion",
  "completion-protocol", "completion-protocol-envelope", "completion-protocol-usage",
  "completion-protocol-tool-result", "completion-protocol-bridge", "completion-protocol-retained",
  "completion-protocol-retained-extract", "completion-protocol-retained-record", "completion-protocol-retained-register",
  "completion-protocol-event", "completion-protocol-envelope-runtime", "completion-protocol-envelope-session-id",
  "completion-protocol-envelope-update-type", "completion-protocol-envelope-before-session",
  "completion-protocol-envelope-early-tool", "completion-protocol-envelope-provisional-session",
  "completion-protocol-envelope-active-session", "completion-protocol-bridge-input",
  "completion-protocol-bridge-tool-name", "completion-protocol-bridge-clone",
  "completion-protocol-bridge-role-access", "completion-protocol-bridge-session",
  "completion-protocol-bridge-invite-shape", "completion-protocol-bridge-invite-send",
  "completion-protocol-bridge-accept", "completion-protocol-bridge-join",
  "completion-protocol-bridge-helper", "completion-protocol-bridge-digest",
  "completion-protocol-bridge-incomplete",
  ...PERMISSION_FAILURE_STAGES.map((stage) => `completion-permission-${stage}`), "completion-stop",
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
    ...(role === "initiator" ? [
      "First call agent_handshake_invite with the four mandate fields as the tool arguments themselves; do not nest them under mandate or terms.",
      "A result whose public body has an error field is not an invitation and must never be copied or used as role access.",
    ] : []),
    "Continue until Clockchain returns a certificate and the retained local verification reports that the certificate is verified.",
    "Follow each MCP result's next action, including waits or retries. Do not end your turn before the verified certificate unless a non-retryable tool error makes completion impossible.",
    "Use the dedicated clockchain-handshake MCP server and retained local-action approvals only.",
  ].join("\n");
}

function continuationPromptText() {
  return [
    "Continue the existing Clockchain handshake from its current MCP state.",
    "Follow the next action returned by the dedicated clockchain-handshake MCP server and use retained local-action approvals only.",
    "Do not end your turn until the local certificate verification is complete, unless a non-retryable tool error makes completion impossible.",
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

function addUsage(left, right) {
  return Object.freeze({
    inputTokens: String(BigInt(left.inputTokens) + BigInt(right.inputTokens)),
    outputTokens: String(BigInt(left.outputTokens) + BigInt(right.outputTokens)),
  });
}

function retainedCommand(value) {
  if (typeof value !== "string" || !/^clockchain-agent-authorize [0-9a-f]{64}$/.test(value)) fail();
  return value.slice("clockchain-agent-authorize ".length);
}

function permissionCommandFailure(stage) {
  if (!PERMISSION_COMMAND_STAGES.includes(stage)) fail();
  const error = new Error("ACP process transport validation failed safely.");
  PERMISSION_COMMAND_FAILURES.set(error, stage);
  return error;
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
  const item = exactObject(value, ["completionStatus", "observeToolResult"]);
  if (typeof item.completionStatus !== "function" || typeof item.observeToolResult !== "function") fail();
  return Object.freeze({ completionStatus: item.completionStatus, observeToolResult: item.observeToolResult });
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

function cleanEnrichedHelperStep(value) {
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

function cleanProductionHelperStep(value, binding) {
  const item = exactObject(value, ["argvAfterVerifiedPrefix", "operation", "shellCommand", "shellCommandSuffix"]);
  if (!HELPER_OPERATIONS.includes(item.operation)) fail();
  const argv = snapshotArray(item.argvAfterVerifiedPrefix, { min: 3, max: 5 });
  if (argv.some((entry) => typeof entry !== "string" || entry.length === 0 || entry.length > MAX_HELPER_COMMAND)) fail();
  const expectedStateDir = `$TMPDIR/.clockchain/handshakes/${binding.sessionId}/${binding.role}`;
  if (
    argv[0] !== item.operation || argv[1] !== "--state-dir" || argv[2] !== expectedStateDir ||
    !(
      argv.length === 3 ||
      argv.length === 5 && argv[3] === "--payload-base64url" && /^[A-Za-z0-9_-]+$/.test(argv[4])
    )
  ) fail();
  const expectedSuffix = argv.map((entry, index) => index === 2 ? `"${entry}"` : entry).join(" ");
  if (item.shellCommandSuffix !== expectedSuffix) fail();
  if (
    typeof item.shellCommand !== "string" || Buffer.byteLength(item.shellCommand) < 1 ||
    Buffer.byteLength(item.shellCommand) > MAX_HELPER_COMMAND ||
    !item.shellCommand.endsWith(` ${expectedSuffix}`) || item.shellCommand.length === expectedSuffix.length + 1
  ) fail();
  const commandSha256 = createHash("sha256").update(item.shellCommand).digest("hex");
  let policyDigest;
  if (argv.length === 5) {
    let payload;
    try {
      const bytes = Buffer.from(argv[4], "base64url");
      if (bytes.length < 1 || bytes.toString("base64url") !== argv[4]) fail();
      payload = JSON.parse(bytes.toString("utf8"));
    } catch {
      fail();
    }
    if (payload !== null && typeof payload === "object" && !Array.isArray(payload) && /^[0-9a-f]{64}$/.test(payload.policyDigest)) {
      policyDigest = payload.policyDigest;
    }
  }
  return Object.freeze({
    approvalCommand: `clockchain-agent-authorize ${commandSha256}`,
    commandLength: Buffer.byteLength(item.shellCommand),
    commandSha256,
    operation: item.operation,
    ...(policyDigest === undefined ? {} : { policyDigest }),
    role: binding.role,
    sessionId: binding.sessionId,
    shellCommand: item.shellCommand,
  });
}

function cleanHelperStep(value, binding) {
  let descriptors;
  try { descriptors = Object.getOwnPropertyDescriptors(value); } catch { fail(); }
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string")) fail();
  if (keys.includes("argvAfterVerifiedPrefix") || keys.includes("shellCommandSuffix")) {
    return cleanProductionHelperStep(value, binding);
  }
  const enriched = cleanEnrichedHelperStep(value);
  if (enriched.role !== binding.role || enriched.sessionId !== binding.sessionId) fail();
  return enriched;
}

function appendHelperStepGroups(value, found, binding) {
  if (value === null || value === undefined) return;
  if (typeof value === "string") {
    let parsed;
    try {
      parsed = JSON.parse(value);
    } catch {
      return;
    }
    appendHelperStepGroups(parsed, found, binding);
    return;
  }
  if (Array.isArray(value)) {
    const blocks = snapshotArray(value);
    for (const blockValue of blocks) {
      const block = exactObject(blockValue, ["text", "type"]);
      if (block.type !== "text") fail();
      appendHelperStepGroups(block.text, found, binding);
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
    found.push(Object.freeze([cleanHelperStep(helperStep, binding)]));
  }
  const helperSteps = descriptors.helperSteps?.value;
  if (helperSteps !== undefined) {
    const group = snapshotArray(helperSteps, { min: 1, max: 3 }).map((step) => cleanHelperStep(step, binding));
    if (group.length > 1 && JSON.stringify(group.map((step) => step.operation)) !== JSON.stringify(["init", "policy", "inspect"])) fail();
    found.push(Object.freeze(group));
  }
  const localAction = descriptors.localAction?.value;
  if (localAction !== undefined) appendHelperStepGroups(localAction, found, binding);
  const structuredContent = descriptors.structuredContent?.value;
  if (structuredContent !== undefined) appendHelperStepGroups(structuredContent, found, binding);
  const content = descriptors.content?.value;
  if (content !== undefined) appendHelperStepGroups(content, found, binding);
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
  if (mcpFailureResult(result)) return null;
  return Object.freeze({ result, toolName });
}

function mcpFailureBody(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string")) return false;
  const expected = descriptors.retryAfterMs === undefined
    ? ["error", "retryable"]
    : ["error", "retryAfterMs", "retryable"];
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) return false;
  for (const key of keys) if (!descriptors[key].enumerable || !Object.hasOwn(descriptors[key], "value")) return false;
  const error = descriptors.error.value;
  const retryable = descriptors.retryable.value;
  if (error === "HANDSHAKE_UNAVAILABLE" && retryable === false && descriptors.retryAfterMs === undefined) return true;
  return error === "HANDSHAKE_TEMPORARILY_UNAVAILABLE" && retryable === true &&
    Number.isSafeInteger(descriptors.retryAfterMs?.value) && descriptors.retryAfterMs.value > 0;
}

function mcpFailureText(value) {
  if (typeof value !== "string" || value.length > MAX_STRING) return false;
  try { return mcpFailureBody(JSON.parse(value)); } catch { return false; }
}

function mcpFailureBlocks(value) {
  if (!Array.isArray(value)) return false;
  const blocks = snapshotArray(value, { min: 1 });
  return blocks.length === 1 && (() => {
    try {
      const block = exactObject(blocks[0], ["text", "type"]);
      return block.type === "text" && mcpFailureText(block.text);
    } catch { return false; }
  })();
}

function mcpFailureResult(value) {
  if (Array.isArray(value)) return mcpFailureBlocks(value);
  if (value === null || typeof value !== "object" || types.isProxy(value)) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const descriptor of Object.values(descriptors)) {
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) return false;
  }
  if (descriptors.isError?.value === true) return true;
  if (mcpFailureBody(descriptors.structuredContent?.value)) return true;
  return mcpFailureBlocks(descriptors.content?.value);
}

function helperStepsFromToolResult(result, actionRecorder, binding) {
  const groups = [];
  appendHelperStepGroups(result, groups, binding);
  if (groups.length === 0) return [];
  if (actionRecorder === null) fail();
  const unique = new Map();
  for (const group of groups) unique.set(digestJson(group), group);
  if (unique.size !== 1) fail();
  return [...unique.values()][0];
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
  const provisionalToolUpdates = [];
  let sessionEstablishing = false;
  let child = null;
  let childMonitor = null;
  let connection = null;
  let completed = false;
  let terminated = false;
  let permissionDenied = false;
  let permissionFailureStage = null;
  let permissionAuthorized = false;
  let protocolFailure = false;
  let protocolFailureStage = null;
  let sessionUpdateBarrier = Promise.resolve();
  let usage = Object.freeze({ inputTokens: "0", outputTokens: "0" });
  const events = [];
  const retainedByCommand = new Map();
  const retainedRegistrationWaiters = new Map();
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
    const waiters = retainedRegistrationWaiters.get(action.commandSha256);
    if (waiters !== undefined) {
      retainedRegistrationWaiters.delete(action.commandSha256);
      for (const waiter of waiters) waiter(true);
    }
    event("acp.retained_action.registered", "registered retained local action", action.commandSha256);
    return action;
  }
  function waitForRetainedRegistration(commandSha256) {
    if (retainedByCommand.has(commandSha256)) return Promise.resolve(true);
    return new Promise((resolve) => {
      const finish = (registered) => {
        clearTimeout(timer);
        const current = retainedRegistrationWaiters.get(commandSha256);
        current?.delete(finish);
        if (current?.size === 0) retainedRegistrationWaiters.delete(commandSha256);
        resolve(registered);
      };
      const timer = setTimeout(() => finish(false), PERMISSION_REGISTRATION_GRACE_MS);
      const waiters = retainedRegistrationWaiters.get(commandSha256) ?? new Set();
      waiters.add(finish);
      retainedRegistrationWaiters.set(commandSha256, waiters);
      if (retainedByCommand.has(commandSha256)) finish(true);
    });
  }
  function cancelRetainedRegistrationWaiters() {
    for (const waiters of retainedRegistrationWaiters.values()) {
      for (const waiter of waiters) waiter(false);
    }
    retainedRegistrationWaiters.clear();
  }
  function permissionCommand(params) {
    const toolCall = params?.toolCall;
    if (toolCall === null || typeof toolCall !== "object" || Array.isArray(toolCall) || types.isProxy(toolCall)) {
      throw permissionCommandFailure("tool");
    }
    let rawInput;
    try { rawInput = optionalObject(toolCall.rawInput, ["command"], ["cwd"]); }
    catch { throw permissionCommandFailure("input"); }
    if (rawInput.cwd !== undefined && rawInput.cwd !== options.workspace) throw permissionCommandFailure("cwd");
    try { return retainedCommand(rawInput.command); }
    catch { throw permissionCommandFailure("approval"); }
  }
  async function requestPermission(params) {
    let denialStage = "session";
    try {
      if (session === null || params?.sessionId !== acpSessionId) fail();
      denialStage = "command";
      const digestValue = permissionCommand(params);
      const barrier = sessionUpdateBarrier;
      await barrier;
      denialStage = "protocol";
      if (protocolFailure) fail();
      if (!retainedByCommand.has(digestValue)) {
        denialStage = "registration";
        if (!await waitForRetainedRegistration(digestValue)) fail();
        const registrationBarrier = sessionUpdateBarrier;
        await registrationBarrier;
        denialStage = "protocol";
        if (protocolFailure) fail();
      }
      denialStage = "state";
      const entry = retainedByCommand.get(digestValue);
      if (entry === undefined || entry.state !== "pending") fail();
      denialStage = "options";
      const optionsList = params?.options;
      if (!Array.isArray(optionsList) || !optionsList.some((option) => option?.optionId === "allow_once" && option?.kind === "allow_once")) fail();
      entry.state = "authorized";
      permissionAuthorized = true;
      event("acp.permission.authorized", "authorized retained local action", digestValue);
      return Object.freeze({ outcome: Object.freeze({ outcome: "selected", optionId: "allow_once" }) });
    } catch (error) {
      permissionDenied = true;
      const commandStage = denialStage === "command" ? PERMISSION_COMMAND_FAILURES.get(error) : null;
      const fixedStage = commandStage === null || commandStage === undefined
        ? denialStage
        : `command-${commandStage}${permissionAuthorized ? "-after-authorization" : ""}`;
      permissionFailureStage ??= PERMISSION_FAILURE_STAGES.includes(fixedStage) ? fixedStage : "unknown";
      return Object.freeze({ outcome: Object.freeze({ outcome: "cancelled" }) });
    }
  }
  async function processSessionUpdate(params) {
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
        failureStage = "envelope-provisional-session";
        if (provisionalAcpSessionId === null) provisionalAcpSessionId = params.sessionId;
        else if (params.sessionId !== provisionalAcpSessionId) fail();
        if (updateType === "tool_call" || updateType === "tool_call_update") {
          const provisionalResult = authoritativeToolResult(params.update);
          if (provisionalResult !== null) {
            failureStage = "envelope-early-tool";
            if (provisionalToolUpdates.length >= MAX_PROVISIONAL_TOOL_UPDATES) fail();
            provisionalToolUpdates.push(params);
            return;
          }
        }
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
            let bridgeResult;
            try {
              bridgeResult = await partyBridge.observeToolResult({ toolName: toolResult.toolName, result: toolResult.result });
            } catch (error) {
              const bridgeStage = directA2APartyBridgeFailureStage(error);
              if (bridgeStage !== null) failureStage = `bridge-${bridgeStage}`;
              throw error;
            }
            const observed = exactObject(bridgeResult, ["observed", "protocolSessionId", "toolResultDigest"]);
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
          failureStage = "retained-extract";
          const retainedSessionId = partyBridge === null ? session.sessionId : protocolSessionId;
          if (retainedSessionId === null) fail();
          const extractedHelperSteps = helperStepsFromToolResult(toolResult.result, actionRecorder, {
            role: session.role,
            sessionId: retainedSessionId,
          });
          failureStage = "retained-record";
          const extractedRetainedActions = extractedHelperSteps.map((step) => validateRetainedLocalAction(actionRecorder.record(step)));
          failureStage = "retained-register";
          for (const retained of extractedRetainedActions) {
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
      cancelRetainedRegistrationWaiters();
    }
  }
  function sessionUpdate(params) {
    const current = sessionUpdateBarrier.then(() => processSessionUpdate(params));
    sessionUpdateBarrier = current;
    return current;
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
      provisionalToolUpdates.length = 0;
      sessionEstablishing = false;
      permissionDenied = false;
      permissionFailureStage = null;
      permissionAuthorized = false;
      sessionUpdateBarrier = Promise.resolve();
      cancelRetainedRegistrationWaiters();
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
        for (const update of provisionalToolUpdates.splice(0)) await sessionUpdate(update);
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
        let promptUsage = Object.freeze({ inputTokens: "0", outputTokens: "0" });
        let bridgeComplete = false;
        for (let promptAttempt = 0; promptAttempt < MAX_COMPLETION_PROMPTS && !bridgeComplete; promptAttempt += 1) {
          launchStage = "prompt";
          const prompted = await connection.prompt({
            sessionId: acpSessionId,
            prompt: [{
              type: "text",
              text: promptAttempt === 0
                ? promptText({ role: clean.role, sessionId: clean.sessionId, mandate: cleanMandateValue, a2aConfig: cleanPeer })
                : continuationPromptText(),
            }],
          });
          launchStage = "completion";
          if (protocolFailure) {
            launchStage = `completion-protocol-${protocolFailureStage ?? "envelope"}`;
            fail();
          }
      if (permissionDenied) {
            launchStage = `completion-permission-${permissionFailureStage ?? "unknown"}`;
            fail();
          }
          if (prompted?.stopReason !== "end_turn") {
            launchStage = "completion-stop";
            fail();
          }
          promptUsage = addUsage(promptUsage, safeUsage(prompted.usage));
          if (partyBridge === null) {
            bridgeComplete = true;
          } else {
            launchStage = "completion-protocol-bridge-incomplete";
            const status = exactObject(partyBridge.completionStatus(), ["complete", "protocolSessionId"]);
            if (
              typeof status.complete !== "boolean" ||
              !(status.protocolSessionId === null || typeof status.protocolSessionId === "string" && status.protocolSessionId.length > 0) ||
              (protocolSessionId !== null && status.protocolSessionId !== protocolSessionId)
            ) fail();
            if (status.protocolSessionId !== null) protocolSessionId = status.protocolSessionId;
            bridgeComplete = status.complete;
          }
          if (!bridgeComplete && promptAttempt + 1 < MAX_COMPLETION_PROMPTS) {
            event("acp.handshake.continue", "continued incomplete Clockchain handshake", String(promptAttempt + 1));
          }
        }
        if (!bridgeComplete) {
          launchStage = "completion-protocol-bridge-incomplete";
          fail();
        }
        usage = promptUsage;
        completed = true;
        event("acp.prompt.end_turn", "ACP prompt completed end_turn", digestJson(usage));
        return Object.freeze({ sessionId: clean.sessionId, role: clean.role, harness });
      } catch {
        cancelRetainedRegistrationWaiters();
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
      cancelRetainedRegistrationWaiters();
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
