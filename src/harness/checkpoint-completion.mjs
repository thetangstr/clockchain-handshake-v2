import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { join } from "node:path";

import { privateKeyToAccount } from "viem/accounts";

import { AGENT_HANDSHAKE_HELPER_VERSION } from "../agent-handshake/v2/constants.mjs";
import { digestHex } from "../core/canonical.mjs";
import { readPrivateText } from "../core/private-path.mjs";

const ROLES = Object.freeze(["initiator", "responder"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const PUBLIC_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const PRIVATE_KEY = /^0x[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const ROLE_TOKEN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
export const ROLE_ACCESS_HANDLE = /^ccra_[A-Za-z0-9_-]{22}$/;
const HELPER_RESULT_SCHEMA = "clockchain.agent-handshake-cli-result/v1";
const CHECKPOINT_OPERATIONS = Object.freeze(["proposal", "acceptance"]);
const CLOCKCHAIN_V2_TOOLS = Object.freeze([
  "agent_handshake_invite",
  "agent_handshake_accept_invitation",
  "agent_handshake_join",
  "agent_handshake_status",
  "agent_handshake_next",
  "agent_handshake_submit_checkpoint",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);

function fail() {
  throw new Error("Checkpoint completion failed safely.");
}

function toolUnavailable(tool) {
  const error = new Error("Checkpoint completion failed safely.");
  error.code = "MCP_TOOL_UNAVAILABLE";
  error.tool = tool;
  throw error;
}

function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail();
  const result = {};
  for (const key of keys) result[key] = value[key];
  return result;
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
    request?.helperVersion !== AGENT_HANDSHAKE_HELPER_VERSION ||
    !["identity_claim", "proposal", "acceptance", "evidence"].includes(request.operation) ||
    !ROLES.includes(request.role) ||
    !UUID.test(request.sessionId ?? "") ||
    !DIGEST.test(request.policyDigest ?? "") ||
    !DIGEST.test(request.bytesSha256 ?? "") ||
    typeof request.bytesGzipBase64Url !== "string" ||
    !BASE64URL.test(request.bytesGzipBase64Url)
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
    !CHECKPOINT_OPERATIONS.includes(artifactType) ||
    !ROLES.includes(role) ||
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
        clientInfo: { name: "clockchain-adapter-checkpoint", version: "1.0.0" },
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
      // Preserve that boundary while letting the caller distinguish service
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

function roleAccessClaims(value) {
  if (typeof value !== "string" || !ROLE_TOKEN.test(value)) fail();
  try {
    const parsed = JSON.parse(Buffer.from(value.split(".")[0], "base64url").toString("utf8"));
    if (!ROLES.includes(parsed?.role) || !UUID.test(parsed?.sessionId ?? "")) fail();
    return Object.freeze({ role: parsed.role, sessionId: parsed.sessionId });
  } catch {
    fail();
  }
}

export function roleAccessBinding(value) {
  if (typeof value === "string") {
    if (ROLE_ACCESS_HANDLE.test(value)) return value;
    const claims = roleAccessClaims(value);
    return Object.freeze({ access: value, ...claims });
  }
  const binding = exactObject(value, ["access", "role", "sessionId"]);
  if (
    typeof binding.access !== "string" ||
    (!ROLE_ACCESS_HANDLE.test(binding.access) && !ROLE_TOKEN.test(binding.access)) ||
    !ROLES.includes(binding.role) || !UUID.test(binding.sessionId)
  ) fail();
  return Object.freeze({ ...binding });
}

function signingPayload(request) {
  let bytes;
  try {
    bytes = gunzipSync(Buffer.from(request.bytesGzipBase64Url, "base64url"));
  } catch {
    fail();
  }
  if (createHash("sha256").update(bytes).digest("hex") !== request.bytesSha256) fail();
  try { return JSON.parse(bytes.toString("utf8")); } catch { fail(); }
}

// Per-role completion boundary for the verified-release action recorder. The
// handler is invoked only after the adapter executable has run the retained
// helper action; for proposal/acceptance sign operations it additionally
// builds, signs, and submits the private commitment checkpoint before
// acknowledging completion. bindRoleAccess must be fed the role access the
// model observed in its MCP stream before any checkpoint submission is
// possible — submissions without a bound handle fail closed.
export function createCheckpointCompletionHandler({ checkpointState, getCheckpointClient, now = Date.now } = {}) {
  if (checkpointState === null || typeof checkpointState !== "object" || Array.isArray(checkpointState)) fail();
  if (typeof getCheckpointClient !== "function") fail();
  let roleAccess = null;

  function bindRoleAccess(value) {
    const binding = roleAccessBinding(value);
    if (typeof binding === "string") {
      if (roleAccess === null || roleAccess.access !== binding) fail();
      return;
    }
    if (roleAccess !== null && JSON.stringify(roleAccess) !== JSON.stringify(binding)) fail();
    roleAccess = binding;
  }

  async function handler(completion) {
    if (
      completion === null || typeof completion !== "object" || Array.isArray(completion) ||
      completion.result === null || typeof completion.result !== "object" || Array.isArray(completion.result)
    ) fail();
    if (completion.operation !== "sign") return Object.freeze({ accepted: true });
    const request = extractSigningRequestFromArgv(completion.argv);
    if (!CHECKPOINT_OPERATIONS.includes(request.operation)) return Object.freeze({ accepted: true });
    if (roleAccess === null) fail();
    if (roleAccess.role !== request.role || roleAccess.sessionId !== request.sessionId) fail();
    if (request.role !== completion.role || request.sessionId !== completion.sessionId) fail();
    const helperResult = completion.result;
    if (
      helperResult.schema !== HELPER_RESULT_SCHEMA ||
      helperResult.helperVersion !== AGENT_HANDSHAKE_HELPER_VERSION ||
      helperResult.operation !== "sign" || helperResult.bytesSha256 !== request.bytesSha256 ||
      !SIGNATURE.test(helperResult.signatureHex ?? "") || !PUBLIC_ADDRESS.test(helperResult.address ?? "")
    ) fail();
    let wallet;
    try {
      wallet = JSON.parse(await readPrivateText({ path: join(completion.stateDir, "wallet.json"), maxBytes: 16 * 1024 }));
    } catch {
      fail();
    }
    if (typeof wallet?.privateKey !== "string" || !PRIVATE_KEY.test(wallet.privateKey)) fail();
    const account = privateKeyToAccount(wallet.privateKey);
    const address = account.address.toLowerCase();
    if (address !== String(wallet.address ?? "").toLowerCase() || address !== helperResult.address.toLowerCase()) fail();
    const previousCheckpoint = request.operation === "proposal" ? null : checkpointState.proposal;
    if (request.operation === "acceptance" && previousCheckpoint === undefined) fail();
    const checkpoint = await createCommitmentCheckpoint({
      artifactPayload: signingPayload(request),
      artifactSignatureHex: helperResult.signatureHex,
      artifactType: request.operation,
      nowMs: now(),
      previousCheckpoint,
      role: request.role,
      sessionId: request.sessionId,
      signerAddress: address,
      signMessage: ({ raw }) => account.signMessage({ message: { raw } }),
    });
    if (JSON.stringify(checkpoint).includes(wallet.privateKey.slice(2).toLowerCase())) fail();
    const client = await getCheckpointClient();
    if (client === null || typeof client?.callTool !== "function") fail();
    const submitted = await client.callTool("agent_handshake_submit_checkpoint", {
      access: roleAccess.access,
      artifactSignatureHex: helperResult.signatureHex,
      checkpoint,
    });
    const checkpointDigest = commitmentCheckpointDigest(checkpoint);
    if (submitted?.checkpointDigest !== checkpointDigest) fail();
    checkpointState[request.operation] = checkpoint;
    return Object.freeze({ accepted: true });
  }

  return Object.freeze({ bindRoleAccess, handler });
}
