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
const VERIFY_CERTIFICATE_PAYLOAD_SCHEMA = "clockchain.agent-handshake-certificate-verification/v1";
const TERMINAL_PROOF_SCHEMA = "clockchain.fresh-agent-terminal-proof/v1";
const RESULT_SCHEMA = "clockchain.agent-handshake-result/v2";
const ANCHOR_KINDS = Object.freeze(["proposal", "acceptance", "acknowledgment"]);
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const TRANSACTION = /^0x[0-9a-f]{64}$/;
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

// Decodes the operation payload embedded in a step's argv.
function argvPayload(argv) {
  if (!Array.isArray(argv) || argv.some((entry) => typeof entry !== "string")) fail();
  const flag = argv.indexOf("--payload-base64url");
  if (flag < 0 || flag !== argv.length - 2 || argv[flag + 1].length === 0) fail();
  try {
    const bytes = Buffer.from(argv[flag + 1], "base64url");
    if (bytes.toString("base64url") !== argv[flag + 1]) fail();
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    fail();
  }
}

export function extractSigningRequestFromArgv(argv) {
  const request = argvPayload(argv);
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

export const CONTINUATION_TOOL_BY_OPERATION = Object.freeze({
  inspect: "agent_handshake_join",
  register: "agent_handshake_next",
  sign: "agent_handshake_submit",
});
const CONTINUATION_FREE = Object.freeze(["init", "policy"]);

// Bounded next-advancement contract: after a trusted submit or registration,
// the completion handler itself polls agent_handshake_next over the
// authenticated client until the coordinator issues the next local action.
// The model never drives this loop; progress no longer depends on it
// choosing to call next after an accepted local action.
const NEXT_CONTINUE_ACTION = "call_agent_handshake_next_with_unchanged_role_access";
const NEXT_JOIN_ACTION = "call_agent_handshake_join_now_with_access_and_exact_init_policy_inspect_outputs";
const NEXT_FUNDING_ACTION = "wait_for_clockchain_host_funding_then_call_agent_handshake_next_with_unchanged_role_access";
const NEXT_FUNDING_VISIBILITY_ACTION = "wait_for_clockchain_host_funding_visibility_then_call_agent_handshake_next_with_unchanged_role_access";
const NEXT_ACTIONS = Object.freeze([NEXT_CONTINUE_ACTION, NEXT_JOIN_ACTION, NEXT_FUNDING_ACTION, NEXT_FUNDING_VISIBILITY_ACTION]);
const NEXT_STAGES = Object.freeze([
  "awaiting_anchors", "awaiting_certificate", "awaiting_counterpart",
  "awaiting_descriptor", "awaiting_funding", "awaiting_funding_visibility",
  "awaiting_identity_registration", "awaiting_proposal", "certificate_available",
  "invited", "party_ready", "sign_acceptance", "sign_evidence", "sign_identity",
  "sign_proposal",
]);
const NEXT_NEEDED = Object.freeze([
  "agent_handshake_join", "certificate", "counterpart_identity",
  "counterpart_transition", "descriptor", "erc8004_registration",
  "funding_record", "funding_visibility", "proposal",
]);
// Each dependency-wait stage carries one exact needed/nextAction pair from
// the coordinator contract; funding waits use their own literal directives.
const WAIT_RESPONSE_BY_STAGE = Object.freeze({
  awaiting_anchors: Object.freeze({ needed: "counterpart_transition", nextAction: NEXT_CONTINUE_ACTION }),
  awaiting_certificate: Object.freeze({ needed: "certificate", nextAction: NEXT_CONTINUE_ACTION }),
  awaiting_counterpart: Object.freeze({ needed: "counterpart_identity", nextAction: NEXT_CONTINUE_ACTION }),
  awaiting_descriptor: Object.freeze({ needed: "descriptor", nextAction: NEXT_CONTINUE_ACTION }),
  awaiting_funding: Object.freeze({ needed: "funding_record", nextAction: NEXT_FUNDING_ACTION }),
  awaiting_funding_visibility: Object.freeze({ needed: "funding_visibility", nextAction: NEXT_FUNDING_VISIBILITY_ACTION }),
  awaiting_proposal: Object.freeze({ needed: "proposal", nextAction: NEXT_CONTINUE_ACTION }),
});
const ADVANCE_MAX_CALLS = 16;
const ADVANCE_WAIT_CAP_MS = 15_000;
// The coordinator only emits 3000/5000; anything larger or non-positive is
// treated as malformed rather than followed.
const MAX_RETRY_AFTER_HINT_MS = 15_000;
// The whole advance sequence must finish safely below the 60-second
// completion-socket deadline; the reserve leaves room for the requeue and
// the accepted write after the final call returns.
const ADVANCE_BUDGET_MS = 45_000;
const ADVANCE_RESERVE_MS = 5_000;

// Per-role completion boundary for the verified-release action recorder. The
// handler is invoked only after the adapter executable has run the retained
// helper action; it then performs the allowlisted deterministic continuation
// for that operation — join after the final setup helper, a bounded next after
// registration, and submit after every signing operation — over the trusted
// authenticated client with the bound role access, so progress never depends
// on the model choosing to continue. For proposal/acceptance sign operations
// it additionally builds, signs, and submits the private commitment
// checkpoint before the public submit. Every trusted continuation result is
// handed to recordSteps so newly issued local actions queue before the
// completion is acknowledged. bindRoleAccess must be fed the role access the
// model observed in its MCP stream before any continuation is possible —
// submissions without a bound handle fail closed.
export function createCheckpointCompletionHandler({ advanceBudgetMs = ADVANCE_BUDGET_MS, checkpointState, getCheckpointClient, onAdvance, onTerminal, recordSteps, now = Date.now } = {}) {
  if (checkpointState === null || typeof checkpointState !== "object" || Array.isArray(checkpointState)) fail();
  if (typeof getCheckpointClient !== "function") fail();
  if (recordSteps !== undefined && typeof recordSteps !== "function") fail();
  if (onAdvance !== undefined && typeof onAdvance !== "function") fail();
  if (onTerminal !== undefined && typeof onTerminal !== "function") fail();
  if (!Number.isSafeInteger(advanceBudgetMs) || advanceBudgetMs < 1_000 || advanceBudgetMs > ADVANCE_BUDGET_MS) fail();
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

  // The recorder turns each trusted continuation result into newly staged
  // actions. A recorder failure must reject the completion rather than let a
  // silently dropped local action strand the handshake. Continuations that
  // must yield a next action (join) require at least one enqueued step.
  async function requeueTrusted(result, { required = false } = {}) {
    if (recordSteps === undefined) {
      if (required) fail();
      return;
    }
    let count;
    try { count = await recordSteps(result); } catch { fail(); }
    if (!Number.isSafeInteger(count) || count < 0 || (required && count < 1)) fail();
  }

  async function clientOrFail() {
    let client;
    try { client = await getCheckpointClient(); } catch { fail(); }
    if (client === null || typeof client?.callTool !== "function") fail();
    return client;
  }

  function boundAccessFor(completion) {
    if (roleAccess === null) fail();
    if (roleAccess.role !== completion.role || roleAccess.sessionId !== completion.sessionId) fail();
    return roleAccess;
  }

  // Validates one trusted agent_handshake_next result against the exact
  // coordinator response contract: a localAction makes it actionable, a
  // retryAfterMs marks a dependency wait, and party_ready with the continue
  // nextAction is an immediate re-poll signal. Anything else fails closed.
  function classifyNextResult(result, completion) {
    if (result === null || typeof result !== "object" || Array.isArray(result)) fail();
    if (result.role !== undefined && result.role !== completion.role) fail();
    if (result.sessionId !== undefined && result.sessionId !== completion.sessionId) fail();
    if (result.stage !== undefined && !NEXT_STAGES.includes(result.stage)) fail();
    if (result.nextAction !== undefined && !NEXT_ACTIONS.includes(result.nextAction)) fail();
    if (result.needed !== undefined && result.needed !== null && !NEXT_NEEDED.includes(result.needed)) fail();
    const hasAction = result.localAction !== undefined && result.localAction !== null;
    const hasWait = result.retryAfterMs !== undefined;
    if (hasAction && hasWait) fail();
    if (hasAction) {
      if (typeof result.localAction !== "object" || Array.isArray(result.localAction)) fail();
      if (result.stage === undefined) {
        // The deployed coordinator's certificateResponse is the only
        // stage-less action: exact top-level and summary contract, bound
        // to this completion's role/session, carrying the verify-certificate
        // helper step the recorder requeues.
        if (result.role !== completion.role || result.sessionId !== completion.sessionId) fail();
        if (result.needed !== undefined || result.nextAction !== undefined) fail();
        const summary = result.certificateSummary;
        if (summary === null || typeof summary !== "object" || Array.isArray(summary)) fail();
        if (
          summary.schema !== "clockchain.agent-handshake-certificate-summary/v1" ||
          summary.outcome !== "VERIFIED" || !DIGEST.test(summary.resultDigest ?? "") ||
          summary.role !== completion.role || summary.sessionId !== completion.sessionId
        ) fail();
        // The localAction envelope itself must be the exact certificate
        // contract — a generic wrapper around a certificate-looking summary
        // is not the coordinator's response.
        const envelope = result.localAction;
        if (
          envelope.executor !== "pinned_helper" ||
          envelope.operation !== "verify-certificate" ||
          envelope.stateDir !== "reuse_exact_absolute_state_dir" ||
          envelope.terminalProof !== "use_verified_helper_output_only"
        ) fail();
        const step = envelope.helperStep;
        if (
          step === null || typeof step !== "object" || Array.isArray(step) ||
          step.operation !== "verify-certificate" ||
          step.role !== completion.role || step.sessionId !== completion.sessionId
        ) fail();
        return "action";
      }
      if (!NEXT_STAGES.includes(result.stage)) fail();
      return "action";
    }
    if (hasWait) {
      // A wait is only valid as the full documented shape for its stage:
      // the stage's exact needed dependency and nextAction literal, plus a
      // positive bounded retryAfterMs. Bare or partial wait objects, and
      // any stage/needed/action mix-and-match, fail closed.
      if (!Number.isSafeInteger(result.retryAfterMs) || result.retryAfterMs <= 0 || result.retryAfterMs > MAX_RETRY_AFTER_HINT_MS) fail();
      const waitSpec = WAIT_RESPONSE_BY_STAGE[result.stage];
      if (waitSpec === undefined) fail();
      if (result.needed !== waitSpec.needed || result.nextAction !== waitSpec.nextAction) fail();
      return "wait";
    }
    if (result.stage === "party_ready" && result.needed === null && result.nextAction === NEXT_CONTINUE_ACTION) return "continue";
    fail();
  }

  // Drives agent_handshake_next until the coordinator issues the next local
  // action, which is requeued through the recorder so the adapter drain picks
  // it up. The server long-polls each call for up to waitMs; the loop is
  // bounded by both a fixed call count and a time budget kept safely below
  // the completion-socket deadline. Waits and continues are followed; a
  // malformed, mismatched, or unexpected result — including budget or bound
  // exhaustion — rejects the completion.
  async function advanceNext(client, access, completion) {
    const startedAt = now();
    const deadline = startedAt + advanceBudgetMs;
    let calls = 0;
    // Diagnostics stay metadata-only: the stage label is a bounded
    // coordinator string, error is a fixed category, never a result body.
    const stageLabel = (result) =>
      typeof result?.stage === "string" && result.stage.length <= 64 ? result.stage : null;
    const neededLabel = (result) =>
      typeof result?.needed === "string" && result.needed.length <= 64 ? result.needed : null;
    const report = (stage, error, needed = null) =>
      onAdvance?.(Object.freeze({
        calls,
        elapsedMs: Math.max(0, now() - startedAt),
        error,
        needed,
        stage,
      }));
    let lastStage = null;
    let lastNeeded = null;
    for (; calls < ADVANCE_MAX_CALLS;) {
      const remaining = deadline - now();
      if (remaining <= ADVANCE_RESERVE_MS) { report(lastStage, "budget", lastNeeded); fail(); }
      let result;
      try {
        result = await client.callTool("agent_handshake_next", {
          access: access.access,
          waitMs: Math.min(remaining - ADVANCE_RESERVE_MS, ADVANCE_WAIT_CAP_MS),
        });
      } catch { report(lastStage, "call", lastNeeded); fail(); }
      calls += 1;
      let kind;
      try { kind = classifyNextResult(result, completion); } catch { report(stageLabel(result), "classify", neededLabel(result)); fail(); }
      if (kind === "action") {
        try { await requeueTrusted(result, { required: true }); }
        catch { report(stageLabel(result), "requeue", neededLabel(result)); fail(); }
        report(stageLabel(result), null, neededLabel(result));
        return;
      }
      lastStage = stageLabel(result);
      lastNeeded = neededLabel(result);
    }
    report(lastStage, "bound", lastNeeded);
    fail();
  }

  // The verify-certificate completion is the only trusted proof source: the
  // pinned helper already verified the certificate signature and binding, so
  // the terminal proof is composed here from the validated helper result and
  // the certificate carried in the step's signed payload — never from model
  // text. Every field is bound to the completion's role/session and to the
  // canonical result inside the step payload.
  function verifyCertificate(completion) {
    boundAccessFor(completion);
    const result = completion.result;
    if (
      result.schema !== HELPER_RESULT_SCHEMA ||
      result.helperVersion !== AGENT_HANDSHAKE_HELPER_VERSION ||
      result.operation !== "verify-certificate" ||
      result.role !== completion.role || result.sessionId !== completion.sessionId ||
      result.certificateVerified !== true || result.outcome !== "VERIFIED" ||
      result.externalBusinessActionPerformed !== false ||
      !DIGEST.test(result.policyDigest ?? "") || !DIGEST.test(result.statementDigest ?? "")
    ) fail();
    const identity = result.identity;
    if (
      identity === null || typeof identity !== "object" || Array.isArray(identity) ||
      !ADDRESS.test(identity.sessionKeyAddress ?? "") ||
      identity.policyDigest !== result.policyDigest
    ) fail();
    const identityErc8004 = identity.erc8004;
    if (
      identityErc8004 === null || typeof identityErc8004 !== "object" || Array.isArray(identityErc8004) ||
      !DECIMAL.test(identityErc8004.agentId ?? "") ||
      !DECIMAL.test(identityErc8004.registrationBlock ?? "") ||
      !TRANSACTION.test(identityErc8004.registrationTx ?? "") ||
      typeof identityErc8004.chainId !== "string" || identityErc8004.chainId.length === 0 ||
      typeof identityErc8004.registryAddress !== "string" || identityErc8004.registryAddress.length === 0 ||
      identityErc8004.reference !== `${identityErc8004.chainId}:${identityErc8004.registryAddress}:${identityErc8004.agentId}`
    ) fail();
    const payload = argvPayload(completion.argv);
    if (
      payload === null || typeof payload !== "object" || Array.isArray(payload) ||
      payload.schema !== VERIFY_CERTIFICATE_PAYLOAD_SCHEMA ||
      payload.helperVersion !== AGENT_HANDSHAKE_HELPER_VERSION ||
      payload.role !== completion.role || payload.sessionId !== completion.sessionId ||
      payload.externalBusinessActionPerformed !== false
    ) fail();
    const certResult = payload.certificate?.result;
    if (
      certResult === null || typeof certResult !== "object" || Array.isArray(certResult) ||
      certResult.schema !== RESULT_SCHEMA ||
      certResult.outcome !== "VERIFIED" ||
      certResult.sessionId !== completion.sessionId ||
      certResult.statementDigest !== result.statementDigest ||
      certResult.externalBusinessActionPerformed !== false ||
      certResult.policyDigests?.[completion.role] !== result.policyDigest
    ) fail();
    const party = certResult.parties?.[completion.role];
    if (
      party === null || typeof party !== "object" || Array.isArray(party) ||
      party.sessionKeyAddress !== identity.sessionKeyAddress ||
      party.policyDigest !== result.policyDigest
    ) fail();
    const partyErc8004 = party.erc8004;
    if (
      partyErc8004 === null || typeof partyErc8004 !== "object" || Array.isArray(partyErc8004) ||
      partyErc8004.agentId !== identityErc8004.agentId ||
      partyErc8004.chainId !== identityErc8004.chainId ||
      partyErc8004.registryAddress !== identityErc8004.registryAddress ||
      partyErc8004.reference !== identityErc8004.reference ||
      partyErc8004.registrationTx !== identityErc8004.registrationTx ||
      partyErc8004.registrationBlock !== identityErc8004.registrationBlock
    ) fail();
    const anchors = certResult.anchors;
    if (!Array.isArray(anchors) || anchors.length !== 3) fail();
    const receiptIds = anchors.map((entry, index) => {
      if (
        entry === null || typeof entry !== "object" || Array.isArray(entry) ||
        entry.kind !== ANCHOR_KINDS[index] || !DIGEST.test(entry.digest ?? "")
      ) fail();
      return entry.digest;
    });
    if (new Set(receiptIds).size !== 3) fail();
    onTerminal?.(Object.freeze({
      schema: TERMINAL_PROOF_SCHEMA,
      role: completion.role,
      sessionId: completion.sessionId,
      policyDigest: result.policyDigest,
      address: identity.sessionKeyAddress,
      erc8004: Object.freeze({
        agentId: identityErc8004.agentId,
        reference: identityErc8004.reference,
        registrationTx: identityErc8004.registrationTx,
        registrationBlock: identityErc8004.registrationBlock,
      }),
      receiptIds: Object.freeze(receiptIds),
      certificateDigest: digestHex(certResult),
      certificateVerified: true,
      externalBusinessActionPerformed: false,
    }));
    return Object.freeze({ accepted: true });
  }

  // Deterministic continuation for non-signing operations: the final setup
  // helper (inspect) carries the committed wallet address and policy digest,
  // so the trusted channel performs the join; register is followed by a
  // bounded next so the model only ever resumes from the next response.
  async function continueNonSigning(completion) {
    const tool = CONTINUATION_TOOL_BY_OPERATION[completion.operation];
    if (tool === undefined) {
      if (completion.operation === "verify-certificate") return verifyCertificate(completion);
      if (CONTINUATION_FREE.includes(completion.operation)) return Object.freeze({ accepted: true });
      fail();
    }
    const access = boundAccessFor(completion);
    const result = completion.result;
    if (
      result.schema !== HELPER_RESULT_SCHEMA ||
      result.helperVersion !== AGENT_HANDSHAKE_HELPER_VERSION ||
      result.operation !== completion.operation
    ) fail();
    const client = await clientOrFail();
    if (tool === "agent_handshake_join") {
      if (!PUBLIC_ADDRESS.test(result.address ?? "") || !DIGEST.test(result.policyDigest ?? "")) fail();
      let joined;
      try {
        joined = await client.callTool(tool, {
          access: access.access,
          helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
          sessionKeyAddress: result.address,
          policyDigest: result.policyDigest,
        });
      } catch { fail(); }
      if (joined?.role !== completion.role || joined?.sessionId !== completion.sessionId) fail();
      await requeueTrusted(joined, { required: true });
    } else {
      // register: the trusted channel advances next until the coordinator
      // issues the following local action.
      if (!PUBLIC_ADDRESS.test(result.address ?? "")) fail();
      await advanceNext(client, access, completion);
    }
    return Object.freeze({ accepted: true });
  }

  async function handler(completion) {
    if (
      completion === null || typeof completion !== "object" || Array.isArray(completion) ||
      completion.result === null || typeof completion.result !== "object" || Array.isArray(completion.result)
    ) fail();
    if (completion.operation !== "sign") return continueNonSigning(completion);
    const request = extractSigningRequestFromArgv(completion.argv);
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
    const client = await clientOrFail();
    if (CHECKPOINT_OPERATIONS.includes(request.operation)) {
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
      let submittedCheckpoint;
      try {
        submittedCheckpoint = await client.callTool("agent_handshake_submit_checkpoint", {
          access: roleAccess.access,
          artifactSignatureHex: helperResult.signatureHex,
          checkpoint,
        });
      } catch { fail(); }
      const checkpointDigest = commitmentCheckpointDigest(checkpoint);
      if (submittedCheckpoint?.checkpointDigest !== checkpointDigest) fail();
      checkpointState[request.operation] = checkpoint;
    }
    let submitted;
    try {
      submitted = await client.callTool("agent_handshake_submit", {
        access: roleAccess.access,
        policyDigest: request.policyDigest,
        signatureHex: helperResult.signatureHex,
      });
    } catch { fail(); }
    const expectedStage = request.operation === "identity_claim" ? "identity_claimed" : `${request.operation}_submitted`;
    if (
      submitted?.role !== request.role || submitted?.sessionId !== request.sessionId ||
      submitted?.stage !== expectedStage
    ) fail();
    await requeueTrusted(submitted);
    // The model cannot be relied on to call next after an accepted sign —
    // the trusted channel advances until the coordinator issues the next
    // local action and requeues it for the adapter drain.
    await advanceNext(client, roleAccess, completion);
    return Object.freeze({ accepted: true });
  }

  return Object.freeze({ bindRoleAccess, handler });
}
