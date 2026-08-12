import { createHash } from "node:crypto";
import { spawn as nodeSpawn } from "node:child_process";

import { ClientSideConnection, ndJsonStream } from "@agentclientprotocol/sdk";

import { validateHarnessEvent } from "./harness-adapter-contract.mjs";
import { ACP_VERSION_PINS } from "./version-pins.mjs";

const MCP_ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
const OPTION_KEYS = Object.freeze([
  "env", "harness", "home", "mcpBearerEnvName", "pin", "sessionEvidence", "spawn", "workspace",
]);
const ROLES = Object.freeze(["initiator", "responder"]);
const SHA = /^[0-9a-f]{64}$/;

function fail() {
  throw new Error("ACP process transport validation failed safely.");
}

function digest(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Object.keys(descriptors);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) fail();
  const result = {};
  for (const key of actual) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    result[key] = descriptor.value;
  }
  return result;
}

function rejectAuthority(value) {
  if (value === null || value === undefined || typeof value !== "object") return;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!descriptor.enumerable) continue;
    if (!Object.hasOwn(descriptor, "value")) fail();
    if (/(?:private.?key|secret.?key|signer|transcript|reasoning|control)/i.test(key)) fail();
    rejectAuthority(descriptor.value);
  }
}

function cleanOptions(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result = {};
  for (const [key, descriptor] of Object.entries(descriptors)) {
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

function cleanA2A(value) {
  const item = exactObject(value, ["endpoint", "peerCard"]);
  const peer = exactObject(item.peerCard, ["endpoint", "id"]);
  if (typeof item.endpoint !== "string" || !item.endpoint.startsWith("https://")) fail();
  if (typeof peer.endpoint !== "string" || !peer.endpoint.startsWith("https://") || typeof peer.id !== "string" || peer.id.length === 0) fail();
  return Object.freeze({ endpoint: item.endpoint, peerCard: Object.freeze({ ...peer }) });
}

function cleanEvidence(value, sessionId, harness, role) {
  const evidence = value ?? {};
  const terminalStatus = evidence.terminalStatus ?? "failed-closed";
  const usage = evidence.usage ?? { inputTokens: "0", outputTokens: "0" };
  if (!["completed", "failed-closed"].includes(terminalStatus)) fail();
  if (!/^(?:0|[1-9][0-9]*)$/.test(usage.inputTokens) || !/^(?:0|[1-9][0-9]*)$/.test(usage.outputTokens)) fail();
  return Object.freeze({
    schema: "clockchain.harness-evidence/v1",
    sessionId,
    harness,
    role,
    terminalStatus,
    usage: Object.freeze({ inputTokens: usage.inputTokens, outputTokens: usage.outputTokens }),
    teardown: Object.freeze({ completed: true }),
  });
}

export function createAcpProcessTransport(optionsInput = {}) {
  const options = cleanOptions(optionsInput);
  const harness = options.harness;
  if (!["codex", "claude"].includes(harness)) fail();
  const pin = cleanPin(options.pin, harness);
  const spawn = options.spawn ?? nodeSpawn;
  if (typeof spawn !== "function") fail();
  for (const key of ["workspace", "home", "mcpBearerEnvName"]) {
    if (typeof options[key] !== "string" || options[key].length === 0) fail();
  }
  const baseEnv = exactObject(options.env ?? {}, Object.keys(options.env ?? {}));
  const bearer = baseEnv[options.mcpBearerEnvName];
  if (typeof bearer !== "string" || bearer.length === 0) fail();
  let session = null;
  let child = null;
  let connection = null;
  const events = [];
  return Object.freeze({
    async launch({ acp, runtime, mandate, mcpEndpoint, a2aConfig }) {
      cleanPin(acp, harness);
      rejectAuthority(mandate);
      if (mcpEndpoint !== MCP_ENDPOINT) fail();
      const clean = cleanRuntime(runtime, harness);
      const cleanPeer = cleanA2A(a2aConfig);
      const env = {
        NODE_ENV: "production",
        HOME: options.home,
        XDG_CACHE_HOME: `${options.home}/.cache`,
        CLOCKCHAIN_MCP_URL: MCP_ENDPOINT,
        CLOCKCHAIN_MCP_AUTH_HEADER: `Authorization: Bearer \${${options.mcpBearerEnvName}}`,
        [options.mcpBearerEnvName]: bearer,
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
      if (typeof child?.stdin?.write === "function" && typeof child?.stdout?.on === "function") {
        connection = new ClientSideConnection({}, ndJsonStream(child.stdout, child.stdin));
      }
      session = { sessionId: clean.sessionId, role: clean.role };
      events.push(validateHarnessEvent({
        schema: "clockchain.harness-event/v1",
        sessionId: clean.sessionId,
        role: clean.role,
        harness,
        sequence: "1",
        type: "acp.process.launch",
        timestampMs: 1786337000000,
        redacted: true,
        publicSummary: `launched ${harness} ACP process`,
        evidenceRef: `sha256:${digest(`${pin.packageName}:${pin.version}:${cleanPeer.peerCard.id}`)}`,
      }));
      return Object.freeze({ sessionId: clean.sessionId, role: clean.role, harness });
    },
    async executeRetainedAction({ sessionId, role, actionId }) {
      if (session === null || session.sessionId !== sessionId || session.role !== role || typeof actionId !== "string" || actionId.length === 0) fail();
      return Object.freeze({ executed: false, actionId, delegatedToAdapter: true });
    },
    async streamEvents({ sessionId }) {
      if (session === null || session.sessionId !== sessionId) fail();
      return Object.freeze(events.map((event) => Object.freeze({ ...event })));
    },
    async terminate({ sessionId, reason = "terminated" }) {
      if (session === null || session.sessionId !== sessionId || typeof reason !== "string") fail();
      child?.kill?.("SIGTERM");
      await connection?.close?.();
      return Object.freeze({ terminated: true });
    },
    async collectEvidence({ sessionId }) {
      if (session === null || session.sessionId !== sessionId) fail();
      const evidence = cleanEvidence(options.sessionEvidence, sessionId, harness, session.role);
      if (/cc_secret|CLOCKCHAIN_MCP_BEARER|transcript|reasoning|\/workspace/i.test(JSON.stringify(evidence))) fail();
      return evidence;
    },
  });
}
