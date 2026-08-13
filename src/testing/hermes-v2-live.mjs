import { createHash } from "node:crypto";

import { digestHex } from "../core/canonical.mjs";

const DIGEST = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const DECISION_KEYS = Object.freeze(["actionDigest", "decision", "reasonCode"]);

export const CLOCKCHAIN_V2_TOOLS = Object.freeze([
  "agent_handshake_invite",
  "agent_handshake_accept_invitation",
  "agent_handshake_join",
  "agent_handshake_status",
  "agent_handshake_next",
  "agent_handshake_submit_checkpoint",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);

export function buildHermesConfig() {
  return Object.freeze({
    _config_version: 33,
    model: Object.freeze({ default: "k3", provider: "kimi-coding" }),
    fallback_providers: Object.freeze([]),
    memory: Object.freeze({ memory_enabled: false, user_profile_enabled: false }),
    hooks: Object.freeze({}),
    hooks_auto_accept: false,
    security: Object.freeze({ redact_secrets: true }),
    mcp_servers: Object.freeze({
      clockchain: Object.freeze({
        url: "https://mcp.clockchain.network/handshake/mcp",
        enabled: true,
        supports_parallel_tool_calls: false,
        connect_timeout: 20,
        tools: Object.freeze({
          include: CLOCKCHAIN_V2_TOOLS,
          exclude: Object.freeze([]),
          prompts: false,
          resources: false,
        }),
      }),
    }),
  });
}

export function buildHermesInvocation({
  cache,
  hermesHome,
  home,
  providerSecret,
  prompt,
  tmp,
  usageFile,
  workspace,
} = {}) {
  for (const value of [cache, hermesHome, home, prompt, providerSecret, tmp, usageFile, workspace]) {
    if (typeof value !== "string" || value.length === 0) fail();
  }
  return Object.freeze({
    args: Object.freeze([
      "-z", prompt,
      "--provider", "kimi-coding",
      "-m", "k3",
      "-t", "file",
      "--ignore-rules",
      "--usage-file", usageFile,
    ]),
    cwd: workspace,
    env: Object.freeze({
      PATH: "/opt/homebrew/opt/node@24/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:/Users/Kailor/.local/bin",
      HOME: home,
      HERMES_HOME: hermesHome,
      XDG_CACHE_HOME: cache,
      TMPDIR: tmp,
      LANG: "en_US.UTF-8",
      LC_ALL: "en_US.UTF-8",
      KIMI_API_KEY: providerSecret,
      HERMES_SKIP_VERSION_CHECK: "1",
    }),
  });
}

function parseRpcBody(text, contentType) {
  if (typeof text !== "string" || text.length === 0) fail();
  if (contentType?.includes("text/event-stream")) {
    const payloads = text.split(/\r?\n/)
      .filter((line) => line.startsWith("data: "))
      .map((line) => line.slice(6));
    if (payloads.length !== 1) fail();
    try { return JSON.parse(payloads[0]); } catch { fail(); }
  }
  try { return JSON.parse(text); } catch { fail(); }
}

export function createStreamableMcpClient({ endpoint, fetchImpl = globalThis.fetch, requestTimeoutMs = 30_000 } = {}) {
  if (
    typeof endpoint !== "string" || !/^https:\/\//.test(endpoint) || typeof fetchImpl !== "function" ||
    !Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > 120_000
  ) fail();
  let requestId = 0;
  let connected = false;

  async function request(method, params, { notification = false } = {}) {
    const body = notification
      ? { jsonrpc: "2.0", method, params }
      : { jsonrpc: "2.0", id: ++requestId, method, params };
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);
    let response;
    try {
      response = await fetchImpl(endpoint, {
        method: "POST",
        headers: {
          accept: "application/json, text/event-stream",
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch {
      fail();
    } finally {
      clearTimeout(timeout);
    }
    if (!response?.ok) fail();
    if (notification) return null;
    const envelope = parseRpcBody(await response.text(), response.headers.get("content-type"));
    if (envelope?.jsonrpc !== "2.0" || envelope?.id !== body.id || envelope.error !== undefined || envelope.result === undefined) fail();
    return envelope.result;
  }

  return Object.freeze({
    async connect() {
      if (connected) return;
      const initialized = await request("initialize", {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "clockchain-hermes-adapter-live-gate", version: "1.0.0" },
      });
      if (initialized?.protocolVersion !== "2025-06-18") fail();
      await request("notifications/initialized", {}, { notification: true });
      connected = true;
    },
    async listTools() {
      if (!connected) fail();
      const listed = await request("tools/list", {});
      if (!Array.isArray(listed?.tools) || listed.tools.some((tool) => typeof tool?.name !== "string")) fail();
      return Object.freeze(listed.tools.map((tool) => tool.name));
    },
    async callTool(name, args) {
      if (!connected || !CLOCKCHAIN_V2_TOOLS.includes(name) || args === null || typeof args !== "object" || Array.isArray(args)) fail();
      const called = await request("tools/call", { name, arguments: args });
      // MCP public tools intentionally return a generic, non-sensitive error body.
      // Preserve that boundary while letting the live runner distinguish service
      // unavailability from a missing local proof.
      if (called?.isError === true) toolUnavailable(name);
      if (!Array.isArray(called?.content)) fail();
      if (called.structuredContent !== undefined) return called.structuredContent;
      const text = called.content.length === 1 && called.content[0]?.type === "text" ? called.content[0].text : null;
      if (typeof text !== "string") fail();
      try { return JSON.parse(text); } catch { fail(); }
    },
  });
}

function fail(code = "HERMES_V2_LIVE_FAILED") {
  const error = new Error("Hermes v2 live gate failed safely.");
  error.code = code;
  throw error;
}

function toolUnavailable(tool) {
  const error = new Error("Hermes v2 live gate failed safely.");
  error.code = "MCP_TOOL_UNAVAILABLE";
  error.tool = tool;
  throw error;
}

function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail();
  const result = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
    result[key] = descriptor.value;
  }
  return result;
}

export function parseHermesDecision(text, { expectedActionDigest } = {}) {
  if (typeof text !== "string" || !DIGEST.test(expectedActionDigest ?? "")) fail();
  let parsed;
  try {
    parsed = JSON.parse(text.trim());
  } catch {
    fail();
  }
  const decision = exactObject(parsed, DECISION_KEYS);
  if (
    !["approve", "refuse"].includes(decision.decision) ||
    decision.actionDigest !== expectedActionDigest ||
    typeof decision.reasonCode !== "string" ||
    !/^[A-Z][A-Z0-9_]{2,63}$/.test(decision.reasonCode)
  ) fail();
  return Object.freeze({ ...decision });
}

export function createHermesDecisionPrompt({ action, policy } = {}) {
  const summary = exactObject(action, ["bytesSha256", "operation", "role", "sessionId"]);
  if (
    !DIGEST.test(summary.bytesSha256) ||
    !["identity_claim", "proposal", "acceptance", "evidence"].includes(summary.operation) ||
    !["initiator", "responder"].includes(summary.role) ||
    !UUID.test(summary.sessionId) ||
    policy === null || typeof policy !== "object" || Array.isArray(policy)
  ) fail();
  const packet = Object.freeze({
    action: Object.freeze({
      operation: summary.operation,
      role: summary.role,
      sessionId: summary.sessionId,
      actionDigest: summary.bytesSha256,
    }),
    localPolicy: policy,
  });
  return [
    "You are an independently controlled stakeholder agent.",
    "Evaluate this public Clockchain action against the immutable local policy below.",
    "actionDigest is an opaque, exact binding for this specific action. It is independently checked by the adapter and is expected to differ from localPolicy.statementDigest; never compare those two digests.",
    "Use localPolicy to judge the role, terms, time limit, identity requirement, and no-external-action boundary. The action packet establishes only the operation, role, session, and opaque binding.",
    "Identity claim is a prerequisite that binds the new local key and policy; fresh ERC-8004 registration happens only after Clockchain funds the new key. Approve that prerequisite when the policy requires a fresh identity.",
    "A proposal or acceptance may be approved only for the stated role and immutable policy. An evidence action from this Clockchain MCP is issued only after the matching handshake artifacts have been verified; its presence is the verified-artifact condition. Never authorize any external business action.",
    "Approve only when the role, reference, statement digest, time limit, identity requirement, and no-external-action boundary match.",
    "Return exactly one JSON object with keys decision, actionDigest, reasonCode. Use decision approve or refuse. Copy actionDigest exactly. For approval reasonCode MUST be the exact uppercase string APPROVE_POLICY_MATCH; for refusal reasonCode MUST be the exact uppercase string REFUSE_POLICY_MISMATCH. Add no markdown or commentary.",
    JSON.stringify(packet),
  ].join("\n");
}

export function extractSigningRequestFromArgv(argv) {
  if (!Array.isArray(argv) || argv.some((entry) => typeof entry !== "string")) fail();
  const flag = argv.indexOf("--payload-base64url");
  if (flag < 0 || flag !== argv.length - 2 || argv[flag + 1].length === 0) fail();
  let request;
  try {
    const bytes = Buffer.from(argv[flag + 1], "base64url");
    if (bytes.toString("base64url") !== argv[flag + 1]) fail();
    request = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail();
  }
  if (
    request?.schema !== "clockchain.agent-handshake-signing-request/v1" ||
    request?.helperVersion !== "2.1.3" ||
    !["identity_claim", "proposal", "acceptance", "evidence"].includes(request.operation) ||
    !["initiator", "responder"].includes(request.role) ||
    !UUID.test(request.sessionId ?? "") ||
    !DIGEST.test(request.policyDigest ?? "") ||
    !DIGEST.test(request.bytesSha256 ?? "") ||
    typeof request.bytesGzipBase64Url !== "string" || request.bytesGzipBase64Url.length === 0
  ) fail();
  return request;
}

function checkpointCanonicalBytes(value, ancestors = new Set(), depth = 0) {
  function normalize(item, level) {
    if (level > 24) fail();
    if (item === null || typeof item === "boolean") return item;
    if (typeof item === "string") {
      if (item.length === 0 || item.length > 512 || item.trim() !== item || !/^[ -~]+$/.test(item)) fail();
      return item;
    }
    if (typeof item === "number") {
      if (!Number.isFinite(item)) fail();
      return item;
    }
    if (typeof item !== "object" || Array.isArray(item) || ancestors.has(item)) fail();
    if (![Object.prototype, null].includes(Object.getPrototypeOf(item))) fail();
    ancestors.add(item);
    try {
      const keys = Reflect.ownKeys(item);
      if (keys.length > 32 || keys.some((key) => typeof key !== "string")) fail();
      const result = {};
      for (const key of keys.sort()) {
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
        result[key] = normalize(descriptor.value, level + 1);
      }
      return result;
    } finally {
      ancestors.delete(item);
    }
  }
  return Buffer.from(JSON.stringify(normalize(value, depth)), "utf8");
}

export function commitmentCheckpointSigningBytes(checkpoint) {
  const item = exactObject(checkpoint, [
    "artifactDigest", "artifactType", "expiresAtMs", "issuedAtMs", "previousCheckpointDigest",
    "protocol", "role", "schema", "sequence", "sessionId", "signature", "signerAddress", "version",
  ]);
  const { signature: _signature, ...unsigned } = item;
  return checkpointCanonicalBytes(unsigned);
}

export function commitmentCheckpointDigest(checkpoint) {
  return createHash("sha256").update(checkpointCanonicalBytes(checkpoint)).digest("hex");
}

export async function createCommitmentCheckpoint({
  artifactPayload,
  artifactSignatureHex,
  artifactType,
  nowMs,
  previousCheckpoint,
  role,
  sessionId,
  signerAddress,
  signMessage,
} = {}) {
  if (
    !["proposal", "acceptance"].includes(artifactType) ||
    !["initiator", "responder"].includes(role) ||
    (artifactType === "proposal" ? role !== "initiator" : role !== "responder") ||
    !UUID.test(sessionId ?? "") || !ADDRESS.test(signerAddress ?? "") ||
    !SIGNATURE.test(artifactSignatureHex ?? "") || !Number.isSafeInteger(nowMs) ||
    typeof signMessage !== "function"
  ) fail();
  const proposal = artifactType === "proposal";
  if (proposal ? previousCheckpoint !== null : previousCheckpoint === null) fail();
  const envelope = {
    payload: artifactPayload,
    schema: `clockchain.agent-handshake-${artifactType}-envelope/v2`,
    signature: { address: signerAddress, algorithm: "eip191", value: artifactSignatureHex },
  };
  const unsigned = {
    schema: "clockchain.agent-handshake-commitment-checkpoint/v1",
    version: "1",
    protocol: "clockchain.agent-handshake/v2",
    sessionId,
    role,
    artifactType,
    artifactDigest: digestHex(envelope),
    sequence: proposal ? "1" : "2",
    previousCheckpointDigest: proposal ? null : commitmentCheckpointDigest(previousCheckpoint),
    issuedAtMs: String(nowMs),
    expiresAtMs: String(nowMs + 60_000),
    signerAddress,
  };
  let signatureHex;
  try {
    signatureHex = await signMessage({ raw: `0x${checkpointCanonicalBytes(unsigned).toString("hex")}` });
  } catch {
    fail();
  }
  if (!SIGNATURE.test(signatureHex ?? "")) fail();
  return Object.freeze({
    ...unsigned,
    signature: Object.freeze({ address: signerAddress, algorithm: "eip191", value: signatureHex }),
  });
}
