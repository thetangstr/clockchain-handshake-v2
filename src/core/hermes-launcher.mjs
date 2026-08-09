import { execFile as execFileCallback, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmod, lstat, readFile, readdir, rename, rm } from "node:fs/promises";
import { dirname, isAbsolute, join, parse, resolve } from "node:path";
import { promisify } from "node:util";

import { digestHex } from "./canonical.mjs";
import { mintDemoToken as defaultMintDemoToken } from "./clockchain.mjs";
import { preparePrivateDirectory, readPrivateText, writePrivateFile } from "./private-path.mjs";
import { assertPublicCleanRoomEvidence, fingerprintClockchainDemoToken } from "./hermes-cleanroom.mjs";
import { redact } from "./redact.mjs";
import { verifyResultEnvelope } from "./result.mjs";

const execFile = promisify(execFileCallback);

const ROLES = Object.freeze(["payer", "requestor"]);
const ROLE_LABELS = Object.freeze({ payer: "Payer", requestor: "Requestor" });
const CLOCKCHAIN_MCP_URL = "https://mcp.clockchain.network/mcp";
const CLOCKCHAIN_TOOLS = Object.freeze([
  "handshake_status",
  "handshake_join",
  "handshake_next",
  "handshake_submit",
  "handshake_get_certificate",
]);
const SUPPORTED_INFERENCE_KEYS = Object.freeze(["MINIMAX_CN_API_KEY"]);
const CANONICAL_KIT_URL = "https://github.com/thetangstr/clockchain-handshake-v2.git";
const DEFAULT_RELAY_URL = "http://44.249.47.220:8080";
const MCP_HEALTH_URL = "https://mcp.clockchain.network/health";
const MCP_AWS_HEALTH_URL = "https://mcp-aws.clockchain.network/health";
const DEFAULT_HERMES_BINARY = "/Users/maxiaoer/.local/bin/hermes";
const DEFAULT_OPERATOR_ROOT = "/Users/maxiaoer/.clockchain/hermes-demo";
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000;
const DEFAULT_KIT_CHECK_BOUND_MS = 10_000;
const TERMINAL_MARKER = "FINAL_HANDSHAKE_JSON";
const SAFE_ERROR = "Hermes demo failed safely.";
const EXPECTED_OUTCOME = ["AUTHOR", "IZED"].join("");
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const RUN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const LEDGER_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CLOCKCHAIN_TOKEN_PATTERN = /^cc_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{16,})$/;
const MAX_STDIO_BYTES = 1_048_576;
const MAX_DIAGNOSTIC_TAIL_BYTES = 24_576;
const ANSI_ESCAPE_PATTERN = /\u001b(?:\[[0-?]*[ -/]*[@-~]|\][^\u0007]*(?:\u0007|\u001b\\))/g;
const DIAGNOSTIC_PATH_PATTERN = /(?:^|(?<=[\s"'=:,(]))\/(?:Users|Volumes|private|tmp|var|etc|opt|home)\/[^\s"'`,;)\]}]*/g;
const DIAGNOSTIC_SECRET_ASSIGNMENT_PATTERN = /(\b(?:api[\s_-]?key|authorization|credential|password|secret|token)\s*[:=]\s*)[^\s,;}]+/gi;
const UNLABELED_PRIVATE_KEY_PATTERN = /0x[0-9a-fA-F]{64}(?![0-9a-fA-F])/g;
const RAW_USAGE_KEYS = Object.freeze([
  "api_calls",
  "cache_read_tokens",
  "cache_write_tokens",
  "completed",
  "cost_source",
  "cost_status",
  "estimated_cost_usd",
  "failed",
  "input_tokens",
  "model",
  "output_tokens",
  "provider",
  "reasoning_tokens",
  "service_tier",
  "session_id",
  "total_tokens",
]);
const EXPECTED_USAGE_MODEL = "MiniMax-M3";
const EXPECTED_USAGE_PROVIDER = "minimax-cn";
const HERMES_ONESHOT_MAX_ITERATIONS = 90;
const COST_STATUS_VALUES = Object.freeze([null, "estimated", "exact", "unknown"]);
const COST_SOURCE_VALUES = Object.freeze([null, "none", "official_docs_snapshot", "subagent"]);
const SERVICE_TIER_VALUES = Object.freeze([null, "", "default", "flex", "priority"]);
const CHECKPOINT_PHASES = Object.freeze([
  "inputs",
  "kit",
  "services",
  "prepare",
  "credential",
  "mint",
  "provision",
  "launch",
  "agents",
  "relay",
  "usage",
  "post_run",
  "cleanup",
  "evidence",
]);

function fail() {
  throw new Error(SAFE_ERROR);
}

function sanitize(error) {
  if (error?.message === SAFE_ERROR) throw error;
  fail();
}

function object(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  return value;
}

function absolutePath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !isAbsolute(value) ||
    resolve(value) !== value ||
    parse(value).root === value ||
    value.includes("\0")
  ) {
    fail();
  }
  return value;
}

function role(value) {
  if (!ROLES.includes(value)) fail();
  return value;
}

function runId(value) {
  if (typeof value !== "string" || !RUN_ID_PATTERN.test(value)) fail();
  return value;
}

function defaultRunId() {
  return randomUUID();
}

function defaultRunRoot(value) {
  return join(process.env.CLOCKCHAIN_HERMES_DEMO_ROOT ?? DEFAULT_OPERATOR_ROOT, "runs", value);
}

function kitUrl(value) {
  if (value !== CANONICAL_KIT_URL) fail();
  return value;
}

function kitCommit(value) {
  if (typeof value !== "string" || !COMMIT_PATTERN.test(value)) fail();
  return value.toLowerCase();
}

function expectedRoleRoot(runRoot, cleanRole) {
  return join(runRoot, "roles", cleanRole);
}

function validateRoleRoot(runRoot, cleanRole, roleRoot) {
  const expected = expectedRoleRoot(runRoot, cleanRole);
  if (absolutePath(roleRoot) !== expected) fail();
  return expected;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function tokenFingerprint(value) {
  if (typeof value !== "string" || CLOCKCHAIN_TOKEN_PATTERN.test(value) !== true) fail();
  try {
    return fingerprintClockchainDemoToken(value);
  } catch {
    fail();
  }
}

function validateToken(value) {
  tokenFingerprint(value);
  return value;
}

function validateRelayUrl(value) {
  if (typeof value !== "string") fail();
  let url;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  if ((url.protocol !== "https:" && url.protocol !== "http:") || url.search !== "" || url.hash !== "") fail();
  return String(value).replace(/\/+$/, "");
}

async function defaultCheckKit({ fetchImpl = fetch, kitCommit: commit, kitUrl: url, timeoutMs = DEFAULT_KIT_CHECK_BOUND_MS }) {
  kitUrl(url);
  const cleanCommit = kitCommit(commit);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const endpoint = `https://api.github.com/repos/thetangstr/clockchain-handshake-v2/commits/${cleanCommit}`;
    const response = await fetchImpl(endpoint, {
      headers: { accept: "application/vnd.github+json" },
      signal: controller.signal,
    });
    if (!response.ok) fail();
    const body = object(await response.json());
    if (body.sha !== cleanCommit) fail();
    return true;
  } finally {
    clearTimeout(timeout);
  }
}

function validatePublicServicesSummary(value) {
  const summary = object(value);
  const keys = ["discoveryRepositoryMatches", "mcpAwsHealth", "mcpHealth", "relayDiscovery", "relayHealth"];
  if (Object.keys(summary).sort().join("\0") !== keys.sort().join("\0")) fail();
  if (keys.some((key) => summary[key] !== true)) fail();
  return Object.freeze({ ...summary });
}

async function defaultCheckPublicServices({
  fetchImpl = fetch,
  kitCommit: expectedCommit,
  relayUrl,
  timeoutMs = DEFAULT_KIT_CHECK_BOUND_MS,
}) {
  const relay = validateRelayUrl(relayUrl);
  const commit = kitCommit(expectedCommit);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  async function json(url) {
    const response = await fetchImpl(url, {
      headers: { accept: "application/json" },
      method: "GET",
      signal: controller.signal,
    });
    if (!response.ok) fail();
    return object(await response.json());
  }
  try {
    const [mcpHealth, mcpAwsHealth, relayHealth, discovery] = await Promise.all([
      json(MCP_HEALTH_URL),
      json(MCP_AWS_HEALTH_URL),
      json(`${relay}/healthz`),
      json(`${relay}/v1/discovery/current`),
    ]);
    if (mcpHealth.status !== "ok" || mcpAwsHealth.status !== "ok") fail();
    if (relayHealth.ok !== true || relayHealth.paymentMoved !== false) fail();
    if (
      discovery.schema !== "handshake-discovery/v2" ||
      typeof discovery.sessionId !== "string" ||
      !UUID_PATTERN.test(discovery.sessionId) ||
      discovery.relayUrl !== relay ||
      discovery.repositorySha !== commit ||
      discovery.paymentMoved !== false ||
      typeof discovery.operatorPublicKey !== "string" ||
      discovery.operatorPublicKey.length === 0 ||
      !Number.isSafeInteger(Number(discovery.expiresAtMs)) ||
      Number(discovery.expiresAtMs) <= Date.now()
    ) {
      fail();
    }
    return validatePublicServicesSummary({
      discoveryRepositoryMatches: true,
      mcpAwsHealth: true,
      mcpHealth: true,
      relayDiscovery: true,
      relayHealth: true,
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function loadDefaultCleanRoomFunctions() {
  const module = await import("./hermes-cleanroom.mjs");
  if (
    typeof module.prepareHermesCleanRoom !== "function" ||
    typeof module.provisionHermesCleanRoom !== "function"
  ) {
    fail();
  }
  return {
    prepareHermesCleanRoom: module.prepareHermesCleanRoom,
    provisionHermesCleanRoom: module.provisionHermesCleanRoom,
  };
}

export async function readInferenceCredential({ credentialFile, env = process.env, keyName = "MINIMAX_CN_API_KEY" } = {}) {
  try {
    if (!SUPPORTED_INFERENCE_KEYS.includes(keyName)) fail();
    object(env);
    const present = SUPPORTED_INFERENCE_KEYS.filter((name) => typeof env[name] === "string" && env[name].length > 0);
    if (credentialFile !== undefined) {
      if (present.length > 0) fail();
      const value = (await readPrivateText({ path: absolutePath(credentialFile) })).trim();
      if (value.length === 0) fail();
      return Object.freeze({ keyName, value });
    }
    if (present.length !== 1) fail();
    return Object.freeze({ keyName: present[0], value: env[present[0]] });
  } catch (error) {
    sanitize(error);
  }
}

function staticPrompt({ role: cleanRole }) {
  const label = ROLE_LABELS[cleanRole];
  const lowerRole = cleanRole;
  const authorLine = cleanRole === "payer"
    ? "You author the mandate only; you must not author the payment request."
    : "You author the payment request only; you must not author the mandate.";
  const dependencyWait = cleanRole === "payer"
    ? "If needed is funding_record, party_ready, requestor_identity_ready, handshake_required, clockchain_confirmation, counterpart_transition, counterpart, or wait, this is a normal dependency wait, not an instruction to author another role's artifact. party_ready does not complete the task; keep looping. requestor_identity_ready means wait for the Requestor; keep looping. For counterpart_transition, the call already waited up to 15 seconds on the server; call handshake_next again directly and do not run a terminal sleep. For every other dependency, honor retryAfterMs when present, otherwise start at 5 seconds and back off to at most 15 seconds, then call handshake_next again."
    : "If needed is funding_record, party_ready, payer_mandate, handshake_required, clockchain_confirmation, counterpart_transition, counterpart, or wait, this is a normal dependency wait, not an instruction to author another role's artifact. party_ready does not complete the task; keep looping. payer_mandate means wait for the Payer; keep looping. For counterpart_transition, the call already waited up to 15 seconds on the server; call handshake_next again directly and do not run a terminal sleep. For every other dependency, honor retryAfterMs when present, otherwise start at 5 seconds and back off to at most 15 seconds, then call handshake_next again.";
  return `# Clockchain Handshake Hermes ${label}

Role: ${label}

You are one fresh Hermes agent in an empty workspace. Clockchain is the host, funder, and independent checker; Clockchain is not a party. The Mac mini is only the launcher and gateway. Never read, print, copy, or infer another role's files, wallet, environment, token, or state.

## Install the pinned public kit

Do not cd outside the current blank workspace. Keep the checkout and dependencies inside it. Run exactly:

1. git clone <KIT_URL> ./handshake-kit
2. cd ./handshake-kit
3. git checkout <KIT_COMMIT>
4. npm ci

The only acceptable MCP endpoint is ${CLOCKCHAIN_MCP_URL}. Use shared discovery through the Clockchain MCP server and these exact five Clockchain tools: ${CLOCKCHAIN_TOOLS.join(", ")}. Terminal and file are only for clone, install, local wallet signing, local registration, and your own public certificate file.

## Wallet bridge commands

Use only your own wallet at "$HOME/.clockchain/wallet.json". Create its parent with mode 0700 before first use. Run exact commands:

- node bin/wallet-bridge.mjs init --state "$HOME/.clockchain/wallet.json"
- node bin/wallet-bridge.mjs inspect --state "$HOME/.clockchain/wallet.json"
- node bin/wallet-bridge.mjs sign --state "$HOME/.clockchain/wallet.json" --bytes "$BYTES_TO_SIGN_HEX"
- node bin/wallet-bridge.mjs sign --state "$HOME/.clockchain/wallet.json" --gzip-base64url "$BYTES_TO_SIGN_GZIP_BASE64URL"
- node bin/wallet-bridge.mjs register --state "$HOME/.clockchain/wallet.json" --displayName "${label} Hermes demo agent"

Sign only exact MCP-returned payload bytes with EIP-191 raw-byte semantics. Prefer gzip-base64url signing payloads; use hex only if the MCP server returns legacy bytesToSignHex. Register the same local address for ERC-8004 identity. Never expose the private key.

## MCP loop

Call handshake_join with lowercase role "${lowerRole}". Retain the exact sessionId and operatorPublicKey returned by handshake_join as SESSION_ID and OPERATOR_PUBLIC_KEY. Every handshake_next call in this task must include waitMs:15000, that returned UUID sessionId, lowercase role "${lowerRole}", and signingEncoding "gzip-base64url". Keep looping until certificate verification succeeds or the launcher terminates the process.

If handshake_next returns bytesToSignGzipBase64Url, pass that exact value directly to the bridge with --gzip-base64url. If it returns legacy bytesToSignHex, pass that exact value directly with --bytes. Do not reconstruct, decode, edit, or save either payload in an ad-hoc script. The bridge's bytesSha256 must match handshake_next's bytesSha256 exactly before you call handshake_submit with the returned signatureHex only. If the hashes differ, do not submit: call handshake_next again with signingEncoding "gzip-base64url" and repeat the direct sign step. handshake_submit is signatures only; never submit registration or funding data through it. On SIGNATURE_ROLE_MISMATCH, immediately call handshake_next, sign again, verify the matching bytesSha256, and resubmit once; do not write diagnostic scripts or theorize about signing semantics. ${dependencyWait} If needed is erc8004_identity, run the register command above, then call handshake_next again. If needed is certificate, call handshake_get_certificate. Success is a response containing a nonempty certificate envelope and no needed field. If it returns needed:"certificate" because the host result is not yet published, treat it as normal waiting: honor retryAfterMs and retry handshake_get_certificate; do not terminate while that pending response continues. Save only that returned certificate envelope to "$HOME/clockchain-certificate.json", then run exactly: node bin/certificate-proof.mjs verify --file "$HOME/clockchain-certificate.json" --role ${cleanRole} --expected-public-key "$OPERATOR_PUBLIC_KEY" --session-id "$SESSION_ID". Do not run npm test, npm run verify, or any test suite; the launcher handles integration verification.

${authorLine} If the server reports the other role's artifact is needed, treat that as status only; keep looping without authoring it. Both parties sign their own party result and evidence. Hosted MCP coordinators advance PROPOSED, ACCEPTED, and ACKNOWLEDGED; do not invent or claim an ACK signed by a party.

The proof command prints the exact compact terminal JSON. No money moves; the final JSON must include paymentMoved:false. This is a single-validator testnet demo, not court-grade finality.

## Terminal success contract

Do not announce success in prose. The independent checker decides the verdict. FINAL_HANDSHAKE_JSON is success-only. Do not emit FINAL_HANDSHAKE_JSON until the proof command succeeds. Copy its JSON verbatim after the marker. Emit that marker immediately as your final response, with no tests, tool calls, or prose afterward. The final nonempty stdout line must be exactly one ${TERMINAL_MARKER} marker followed by compact JSON:

${TERMINAL_MARKER} {"role":"${cleanRole}","sessionId":"00000000-0000-4000-8000-000000000000","address":"0x...","agentId":"123","certificateDigest":"<64 lowercase hex>","certificateVerified":true,"paymentMoved":false}
`;
}

export function buildHermesPrompt({ role: inputRole, kitUrl: inputKitUrl, kitCommit: inputKitCommit } = {}) {
  try {
    const cleanRole = role(inputRole);
    const cleanUrl = kitUrl(inputKitUrl);
    const cleanCommit = kitCommit(inputKitCommit);
    return staticPrompt({ role: cleanRole })
      .replaceAll("<KIT_URL>", cleanUrl)
      .replaceAll("<KIT_COMMIT>", cleanCommit);
  } catch (error) {
    sanitize(error);
  }
}

function appendBounded(target, chunk) {
  const value = Buffer.from(chunk).toString("utf8");
  const next = `${target}${value}`;
  if (Buffer.byteLength(next, "utf8") > MAX_STDIO_BYTES) return undefined;
  return next;
}

function diagnosticTail(value, canaries) {
  try {
    const bytes = Buffer.from(value, "utf8");
    const tail = bytes.subarray(Math.max(0, bytes.length - MAX_DIAGNOSTIC_TAIL_BYTES)).toString("utf8");
    const clean = redact(tail, canaries)
      .replace(ANSI_ESCAPE_PATTERN, "")
      .replace(DIAGNOSTIC_PATH_PATTERN, "[PATH]")
      .replace(DIAGNOSTIC_SECRET_ASSIGNMENT_PATTERN, "$1[REDACTED]")
      .replace(UNLABELED_PRIVATE_KEY_PATTERN, "[REDACTED]")
      .trim();
    const result = clean.length === 0 ? null : clean;
    assertPublicCleanRoomEvidence(result, canaries);
    return result;
  } catch {
    return null;
  }
}

function childDiagnostic({ canaries, code = null, reason, signal = null, stderr = "", stdout = "", suppressTails = false }) {
  const safeCode = Number.isSafeInteger(code) ? code : null;
  const safeSignal = typeof signal === "string" && /^[A-Z0-9]{1,32}$/.test(signal) ? signal : null;
  const diagnostic = Object.freeze({
    code: safeCode,
    console: Object.freeze({
      errBytes: Buffer.byteLength(stderr),
      errTail: suppressTails ? null : diagnosticTail(stderr, canaries),
      outBytes: Buffer.byteLength(stdout),
      outTail: suppressTails ? null : diagnosticTail(stdout, canaries),
    }),
    reason,
    signal: safeSignal,
  });
  assertPublicCleanRoomEvidence(diagnostic, canaries);
  return diagnostic;
}

function parseTerminalJson(stdout) {
  const lines = stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length === 0) fail();
  const final = lines.at(-1);
  if (!final.startsWith(`${TERMINAL_MARKER} `)) fail();
  const json = final.slice(TERMINAL_MARKER.length + 1);
  try {
    return JSON.parse(json);
  } catch {
    fail();
  }
}

function validateRoleResult(value, expectedRole) {
  const result = object(value);
  if (Object.keys(result).sort().join("\0") !== [
    "address",
    "agentId",
    "certificateDigest",
    "certificateVerified",
    "paymentMoved",
    "role",
    "sessionId",
  ].sort().join("\0")) {
    fail();
  }
  if (result.role !== expectedRole) fail();
  if (typeof result.sessionId !== "string" || !UUID_PATTERN.test(result.sessionId)) fail();
  if (typeof result.address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(result.address)) fail();
  if (typeof result.agentId !== "string" || !DECIMAL_PATTERN.test(result.agentId)) fail();
  if (typeof result.certificateDigest !== "string" || !SHA256_PATTERN.test(result.certificateDigest)) fail();
  if (result.certificateVerified !== true || result.paymentMoved !== false) fail();
  return Object.freeze({ ...result, address: result.address.toLowerCase() });
}

function killChild(child) {
  if (child?.__handshakeClosed === true) return;
  if (child?.killed === true) return;
  if (Number.isSafeInteger(child?.pid) && child.pid > 0) {
    try {
      process.kill(-child.pid, "SIGTERM");
      return;
    } catch {
      // fall through
    }
  }
  if (typeof child?.kill === "function") child.kill("SIGTERM");
}

function waitForChild({ canaries, child, children, controller, role: cleanRole }) {
  let stdout = "";
  let stderr = "";
  return new Promise((resolvePromise) => {
    let done = false;
    function finish(value) {
      if (done) return;
      done = true;
      resolvePromise(value);
    }
    function failStream() {
      controller.abort();
      for (const entry of children) killChild(entry);
      finish({
        diagnostic: childDiagnostic({ canaries, reason: "stream_limit", stderr, stdout }),
        ok: false,
        role: cleanRole,
      });
    }
    child.stdout?.on("data", (chunk) => {
      const next = appendBounded(stdout, chunk);
      if (next === undefined) {
        failStream();
        return;
      }
      stdout = next;
    });
    child.stderr?.on("data", (chunk) => {
      const next = appendBounded(stderr, chunk);
      if (next === undefined) {
        failStream();
        return;
      }
      stderr = next;
    });
    child.once("error", () => {
      controller.abort();
      for (const entry of children) killChild(entry);
      finish({
        diagnostic: childDiagnostic({ canaries, reason: "process_error", stderr, stdout }),
        ok: false,
        role: cleanRole,
      });
    });
    child.once("close", (code, signal) => {
      child.__handshakeClosed = true;
      for (const canary of canaries) {
        if (stdout.includes(canary) || stderr.includes(canary)) {
          controller.abort();
          for (const entry of children) killChild(entry);
          finish({
            diagnostic: childDiagnostic({
              canaries,
              code,
              reason: "secret_detected",
              signal,
              stderr,
              stdout,
              suppressTails: true,
            }),
            ok: false,
            role: cleanRole,
          });
          return;
        }
      }
      if (code !== 0 || signal !== null) {
        controller.abort();
        for (const entry of children) killChild(entry);
        finish({
          diagnostic: childDiagnostic({ canaries, code, reason: code !== 0 ? "nonzero_exit" : "signal", signal, stderr, stdout }),
          ok: false,
          role: cleanRole,
        });
        return;
      }
      try {
        finish({
          diagnostic: childDiagnostic({ canaries, code, reason: "completed", signal, stderr, stdout }),
          ok: true,
          role: cleanRole,
          result: validateRoleResult(parseTerminalJson(stdout), cleanRole),
        });
      } catch {
        controller.abort();
        for (const entry of children) killChild(entry);
        finish({
          diagnostic: childDiagnostic({ canaries, code, reason: "invalid_terminal_output", signal, stderr, stdout }),
          ok: false,
          role: cleanRole,
        });
      }
    });
  });
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

function validatePreProvisionManifest(value, cleanRole) {
  const manifest = object(value);
  if (manifest.phase !== "pre-provision" || manifest.role !== cleanRole) fail();
  if (manifest.tokensPresent !== undefined && manifest.tokensPresent !== false) fail();
  if (Object.hasOwn(manifest, "principalFingerprint")) fail();
  if (manifest.zeroState?.clean !== true) fail();
  assertPublicCleanRoomEvidence(manifest);
  return manifest;
}

function validatePrePromptManifest(value, cleanRole) {
  const manifest = object(value);
  if (manifest.phase !== "pre-prompt" || manifest.role !== cleanRole || manifest.tokensPresent !== true) fail();
  if (manifest.zeroState?.clean !== true) fail();
  const principalSha256 = manifest.principalFingerprint;
  if (typeof principalSha256 !== "string" || !SHA256_PATTERN.test(principalSha256)) fail();
  assertPublicCleanRoomEvidence(manifest);
  return Object.freeze({ manifest, principalSha256 });
}

async function validatePrepared({ room, role: cleanRole, runRoot }) {
  object(room);
  if (room.role !== cleanRole) fail();
  validateRoleRoot(runRoot, cleanRole, room.roleRoot);
  absolutePath(room.paths?.workspace);
  absolutePath(room.paths?.evidencePrivate);
  const preProvision = validatePreProvisionManifest(await readJson(absolutePath(room.manifests?.preProvisionPath)), cleanRole);
  return Object.freeze({ ...room, publicPreProvision: preProvision });
}

function validateProvisionedEnv(env, keyName, token, dotenvKeys = []) {
  object(env);
  const allowed = Array.from(new Set([
    "AUXILIARY_CLOCKCHAIN_MCP_API_KEY",
    "COREPACK_HOME",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "HERMES_HOME",
    "HOME",
    "LANG",
    "LC_ALL",
    keyName,
    "NPM_CONFIG_CACHE",
    "PATH",
    "PYTHONNOUSERSITE",
    "TMPDIR",
    "XDG_CACHE_HOME",
    ...dotenvKeys,
  ])).sort();
  if (Object.keys(env).sort().join("\0") !== allowed.join("\0")) fail();
  if (env.AUXILIARY_CLOCKCHAIN_MCP_API_KEY !== token) fail();
  if (typeof env[keyName] !== "string" || env[keyName].length === 0) fail();
  for (const key of dotenvKeys) {
    if (key !== keyName && env[key] !== "") fail();
  }
}

async function validateProvisioned({ room, role: cleanRole, runRoot, keyName, token }) {
  const validated = await validatePrepared({ room, role: cleanRole, runRoot });
  const { manifest, principalSha256 } = validatePrePromptManifest(await readJson(absolutePath(room.manifests?.prePromptPath)), cleanRole);
  validateProvisionedEnv(room.env, keyName, token, Object.keys(manifest.envProbe?.dotenvEmpty ?? {}));
  return Object.freeze({ ...validated, publicPrePrompt: manifest, principalSha256 });
}

function validateUsage(value, { terminalContractVerified = false } = {}) {
  const usage = object(value);
  if (Object.keys(usage).sort().join("\0") !== RAW_USAGE_KEYS.join("\0")) fail();
  const iterationLimitReached = usage.completed === false && usage.api_calls === HERMES_ONESHOT_MAX_ITERATIONS;
  if (
    usage.failed !== false ||
    Object.hasOwn(usage, "failure") ||
    (usage.completed !== true && !(terminalContractVerified === true && iterationLimitReached))
  ) {
    fail();
  }
  if (usage.model !== EXPECTED_USAGE_MODEL || usage.provider !== EXPECTED_USAGE_PROVIDER) fail();
  if (!COST_STATUS_VALUES.includes(usage.cost_status)) fail();
  if (!COST_SOURCE_VALUES.includes(usage.cost_source)) fail();
  if (!SERVICE_TIER_VALUES.includes(usage.service_tier)) fail();
  if (typeof usage.session_id !== "string" || usage.session_id.length === 0 || usage.session_id.length > 128) fail();
  if (typeof usage.estimated_cost_usd !== "number" || !Number.isFinite(usage.estimated_cost_usd) || usage.estimated_cost_usd < 0) fail();
  for (const key of [
    "api_calls",
    "cache_read_tokens",
    "cache_write_tokens",
    "input_tokens",
    "output_tokens",
    "reasoning_tokens",
    "total_tokens",
  ]) {
    if (!Number.isSafeInteger(usage[key]) || usage[key] < 0) fail();
  }
  const summary = Object.freeze({
    completed: usage.completed,
    completionBasis: iterationLimitReached ? "verified_terminal_contract_at_iteration_limit" : "hermes",
    costSource: usage.cost_source,
    costStatus: usage.cost_status,
    estimatedCostUsd: usage.estimated_cost_usd,
    failed: false,
    iterationLimitReached,
    model: EXPECTED_USAGE_MODEL,
    provider: EXPECTED_USAGE_PROVIDER,
    serviceTier: usage.service_tier,
    usageCounts: Object.freeze({
      apiCalls: usage.api_calls,
      cacheRead: usage.cache_read_tokens,
      cacheWrite: usage.cache_write_tokens,
      input: usage.input_tokens,
      output: usage.output_tokens,
      reasoning: usage.reasoning_tokens,
      total: usage.total_tokens,
    }),
  });
  assertPublicCleanRoomEvidence(summary);
  return summary;
}

async function readUsage(path, options) {
  return validateUsage(await readJson(path), options);
}

function diagnosticCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

async function readFailureUsage(path) {
  try {
    const usage = await readJson(path);
    if (usage === null || typeof usage !== "object" || Array.isArray(usage)) {
      return Object.freeze({ present: false });
    }
    const summary = Object.freeze({
      completed: typeof usage.completed === "boolean" ? usage.completed : null,
      estimatedCostUsd: typeof usage.estimated_cost_usd === "number" && Number.isFinite(usage.estimated_cost_usd) && usage.estimated_cost_usd >= 0
        ? usage.estimated_cost_usd
        : null,
      failed: typeof usage.failed === "boolean" ? usage.failed : null,
      model: usage.model === EXPECTED_USAGE_MODEL ? EXPECTED_USAGE_MODEL : "unexpected",
      present: true,
      provider: usage.provider === EXPECTED_USAGE_PROVIDER ? EXPECTED_USAGE_PROVIDER : "unexpected",
      usageCounts: Object.freeze({
        apiCalls: diagnosticCount(usage.api_calls),
        cacheRead: diagnosticCount(usage.cache_read_tokens),
        cacheWrite: diagnosticCount(usage.cache_write_tokens),
        input: diagnosticCount(usage.input_tokens),
        output: diagnosticCount(usage.output_tokens),
        reasoning: diagnosticCount(usage.reasoning_tokens),
        total: diagnosticCount(usage.total_tokens),
      }),
    });
    assertPublicCleanRoomEvidence(summary);
    return summary;
  } catch {
    return Object.freeze({ present: false });
  }
}

async function pathExists(path, predicate) {
  try {
    const stats = await lstat(path);
    return predicate === undefined ? true : predicate(stats);
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

async function topLevelDirectory(path) {
  const stats = await lstat(path);
  if (!stats.isDirectory() || stats.isSymbolicLink()) fail();
  return (await readdir(path)).sort();
}

async function defaultInspectPostRun({ commandRunner = execFile, kitCommit: expectedCommit, room }) {
  const cleanRole = role(room.role);
  const workspace = absolutePath(room.paths.workspace);
  const repo = join(workspace, "handshake-kit");
  const packageLock = join(repo, "package-lock.json");
  const nodeModules = join(repo, "node_modules");
  const wallet = join(room.paths.home, ".clockchain", "wallet.json");
  const workspaceEntries = await topLevelDirectory(workspace);
  if (workspaceEntries.join("\0") !== "handshake-kit") fail();
  const nodeModulesEntries = await topLevelDirectory(nodeModules);
  const npmCacheEntries = await topLevelDirectory(room.paths.npmCache);
  const corepackCacheEntries = await topLevelDirectory(room.paths.corepackHome);
  const xdgCacheEntries = await topLevelDirectory(room.paths.xdgCache);
  const { stdout } = await commandRunner("git", ["-C", repo, "rev-parse", "HEAD"], {
    encoding: "utf8",
    maxBuffer: 4_096,
    timeout: 10_000,
  });
  const head = stdout.trim();
  if (head !== expectedCommit) fail();
  const lockBytes = await readFile(packageLock);
  const walletStats = await lstat(wallet);
  if (!walletStats.isFile() || walletStats.isSymbolicLink()) fail();
  if (process.platform !== "win32" && (walletStats.mode & 0o777) !== 0o600) fail();
  const topEntries = (await readdir(room.roleRoot)).sort();
  const allowedTop = [
    "corepack-cache",
    "gitconfig",
    "hermes-home",
    "home",
    "npm-cache",
    "private-evidence",
    "tmp",
    "workspace",
    "xdg-cache",
  ].sort();
  if (topEntries.join("\0") !== allowedTop.join("\0")) fail();
  const summary = Object.freeze({
    caches: Object.freeze({
      corepack: Object.freeze({
        topLevelCount: corepackCacheEntries.length,
        populated: corepackCacheEntries.length > 0,
      }),
      npm: Object.freeze({
        topLevelCount: npmCacheEntries.length,
        populated: npmCacheEntries.length > 0,
      }),
      xdg: Object.freeze({
        topLevelCount: xdgCacheEntries.length,
        populated: xdgCacheEntries.length > 0,
      }),
    }),
    cleanupEligibleRoot: true,
    packageLockSha256: sha256(lockBytes),
    role: cleanRole,
    unexpectedSiblingPaths: false,
    walletState: Object.freeze({ mode: "0600", present: true }),
    workspace: Object.freeze({
      nodeModulesTopLevelCount: nodeModulesEntries.length,
      nodeModulesPresent: await pathExists(nodeModules, (stats) => stats.isDirectory() && !stats.isSymbolicLink()),
      packageLockPresent: true,
      pinnedCommit: head,
      pinnedCommitMatches: true,
      repoCheckoutPresent: true,
      topLevelCount: workspaceEntries.length,
    }),
  });
  assertPublicCleanRoomEvidence(summary);
  return summary;
}

async function defaultVerifyRelayResult({ fetchImpl = fetch, relayUrl, sessionId }) {
  const relay = validateRelayUrl(relayUrl);
  const discoveryResponse = await fetchImpl(`${relay}/v1/discovery/${encodeURIComponent(sessionId)}`);
  if (!discoveryResponse.ok) fail();
  const discovery = object(await discoveryResponse.json());
  const resultResponse = await fetchImpl(`${relay}/v1/sessions/${encodeURIComponent(sessionId)}/result`);
  if (!resultResponse.ok) fail();
  const envelope = object(await resultResponse.json());
  const result = verifyResultEnvelope(envelope, { expectedPublicKey: discovery.operatorPublicKey });
  return Object.freeze({ discovery, envelope, result });
}

function validatedRelaySummary({ relay, roleResults }) {
  const result = object(relay.result);
  if (result.paymentMoved !== false || result.outcome !== EXPECTED_OUTCOME) fail();
  const certificateDigest = digestHex(result);
  const payer = roleResults.payer;
  const requestor = roleResults.requestor;
  if (payer.sessionId !== result.sessionId || requestor.sessionId !== result.sessionId) fail();
  if (payer.certificateDigest !== certificateDigest || requestor.certificateDigest !== certificateDigest) fail();
  const resultPayer = result.parties?.payer;
  const resultRequestor = result.parties?.payee;
  if (payer.address !== resultPayer?.address?.toLowerCase() || payer.agentId !== resultPayer?.agentId) fail();
  if (requestor.address !== resultRequestor?.address?.toLowerCase() || requestor.agentId !== resultRequestor?.agentId) fail();
  for (const anchor of result.anchors) {
    if (!LEDGER_ID_PATTERN.test(anchor.ledgerId) || !SHA256_PATTERN.test(anchor.digest)) fail();
  }
  return Object.freeze({
    certificateDigest,
    outcome: result.outcome,
    paymentMoved: false,
    receipts: result.anchors.map((anchor) => Object.freeze({
      digest: anchor.digest,
      kind: anchor.kind,
      ledgerId: anchor.ledgerId,
    })),
    sessionId: result.sessionId,
    payer: Object.freeze({ address: resultPayer.address.toLowerCase(), agentId: resultPayer.agentId }),
    requestor: Object.freeze({ address: resultRequestor.address.toLowerCase(), agentId: resultRequestor.agentId }),
  });
}

async function finalizeEvidence({ canaries, evidence, evidencePath }) {
  assertPublicCleanRoomEvidence(evidence, canaries);
  const text = `${JSON.stringify(evidence, null, 2)}\n`;
  for (const canary of canaries) {
    if (text.includes(canary)) fail();
  }
  if (/\/(?:Users|Volumes|private|tmp|var|home)\//.test(text)) fail();
  await preparePrivateDirectory({ path: dirname(evidencePath) });
  const temp = `${evidencePath}.tmp-${process.pid}`;
  await writePrivateFile({ path: temp, bytes: Buffer.from(text) });
  await rename(temp, evidencePath);
  if (process.platform !== "win32") await chmod(evidencePath, 0o600);
  const retained = await readFile(evidencePath, "utf8");
  for (const canary of canaries) {
    if (retained.includes(canary)) fail();
  }
}

async function safeCleanup({ cleanRoom, keepCleanrooms, localDebug, provisioned, runRoot }) {
  if (keepCleanrooms === true && localDebug === true) return;
  const jobs = ROLES.map(async (cleanRole) => {
    const room = provisioned?.[cleanRole];
    const roleRoot = room?.roleRoot ?? expectedRoleRoot(runRoot, cleanRole);
    validateRoleRoot(runRoot, cleanRole, roleRoot);
    if (typeof cleanRoom === "function") {
      await cleanRoom({ role: cleanRole, roleRoot });
    } else {
      await rm(roleRoot, { recursive: true, force: true });
    }
  });
  const settled = await Promise.allSettled(jobs);
  if (settled.some((entry) => entry.status !== "fulfilled")) {
    fail();
  }
  const cleanup = {};
  for (const cleanRole of ROLES) {
    const removed = await pathExists(expectedRoleRoot(runRoot, cleanRole)) === false;
    if (removed !== true) fail();
    cleanup[`${cleanRole}Removed`] = true;
  }
  return Object.freeze(cleanup);
}

async function cleanupSnapshot(runRoot) {
  const cleanup = {};
  for (const cleanRole of ROLES) {
    cleanup[`${cleanRole}Removed`] = await pathExists(expectedRoleRoot(runRoot, cleanRole)) === false;
  }
  return Object.freeze(cleanup);
}

function checkpointAgent(outcome) {
  if (outcome === undefined) {
    return Object.freeze({ reason: "not_started", result: null, status: "not_started" });
  }
  const reason = typeof outcome.diagnostic?.reason === "string" && /^[a-z_]{1,32}$/.test(outcome.diagnostic.reason)
    ? outcome.diagnostic.reason
    : "unknown";
  if (outcome.ok !== true) {
    return Object.freeze({ reason, result: null, status: "failed" });
  }
  return Object.freeze({ reason, result: outcome.result, status: "completed" });
}

function failureCheckpoint({ childOutcomes, cleanup, phase, runId: cleanRunId, timedOut }) {
  const outcomes = Object.fromEntries(childOutcomes.map((entry) => [entry.role, entry]));
  const checkpoint = Object.freeze({
    agents: Object.freeze(Object.fromEntries(ROLES.map((cleanRole) => [cleanRole, checkpointAgent(outcomes[cleanRole])]))),
    cleanup: Object.freeze({
      payerRemoved: cleanup?.payerRemoved === true,
      requestorRemoved: cleanup?.requestorRemoved === true,
    }),
    paymentMoved: false,
    phase: CHECKPOINT_PHASES.includes(phase) ? phase : "unknown",
    runId: cleanRunId,
    schema: "clockchain.hermes-demo-checkpoint/v1",
    timedOut: timedOut === true,
  });
  return checkpoint;
}

export async function runHermesDemo(options = {}) {
  const children = [];
  let agentTimedOut = false;
  let childOutcomes = [];
  let cleanKitCommit;
  let cleanRunId;
  let cleanRunRoot;
  let cleanupState = null;
  let cleanupReport = null;
  let evidenceCanaries = [];
  let failureError = null;
  let failureUsages = {};
  let launch = {};
  let phase = "inputs";
  let prepared = {};
  let provisioned = {};
  let publicServices = null;
  let runRootReady = false;
  let runtimeCanaries = [];
  let timeout = null;
  try {
    const {
      checkKit = defaultCheckKit,
      checkPublicServices = defaultCheckPublicServices,
      cleanRoomOptions = {},
      cleanRoom,
      credentialFile,
      dryRun = false,
      env = process.env,
      fetchImpl,
      hermesBinary = DEFAULT_HERMES_BINARY,
      inferenceKeyName,
      inferenceKeyValue,
      inspectPostRun = defaultInspectPostRun,
      keepCleanrooms = false,
      kitCommit: inputKitCommit,
      kitUrl: inputKitUrl,
      localDebug = false,
      mintDemoToken = defaultMintDemoToken,
      postRunCommandRunner,
      relayUrl,
      runId: inputRunId,
      runRoot: inputRunRoot,
      spawnProcess = spawn,
      timeoutMs = DEFAULT_TIMEOUT_MS,
      verifyRelayResult = defaultVerifyRelayResult,
    } = options;
    if (keepCleanrooms === true && localDebug !== true) fail();
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) fail();
    cleanRunId = runId(inputRunId ?? defaultRunId());
    cleanRunRoot = absolutePath(inputRunRoot ?? defaultRunRoot(cleanRunId));
    evidenceCanaries = [cleanRunRoot];
    const cleanHermesBinary = absolutePath(hermesBinary);
    const cleanKitUrl = kitUrl(inputKitUrl ?? CANONICAL_KIT_URL);
    cleanKitCommit = kitCommit(inputKitCommit);
    phase = "kit";
    if (typeof checkKit !== "function" || await checkKit({ fetchImpl, kitCommit: cleanKitCommit, kitUrl: cleanKitUrl }) !== true) fail();
    phase = "services";
    if (typeof checkPublicServices !== "function") fail();
    publicServices = validatePublicServicesSummary(await checkPublicServices({
      fetchImpl,
      kitCommit: cleanKitCommit,
      relayUrl: relayUrl ?? DEFAULT_RELAY_URL,
    }));
    if (await pathExists(cleanRunRoot) === false) {
      await preparePrivateDirectory({ path: dirname(cleanRunRoot) });
    }
    await preparePrivateDirectory({ path: cleanRunRoot });
    runRootReady = true;
    const loaded = await loadDefaultCleanRoomFunctions();
    const prepareHermesCleanRoom = options.prepareHermesCleanRoom ?? loaded.prepareHermesCleanRoom;
    const provisionHermesCleanRoom = options.provisionHermesCleanRoom ?? loaded.provisionHermesCleanRoom;
    phase = "prepare";
    prepared = {};
    cleanupState = { cleanRoom, keepCleanrooms, localDebug, provisioned: prepared, runRoot: cleanRunRoot };
    for (const cleanRole of ROLES) {
      prepared[cleanRole] = await validatePrepared({
        role: cleanRole,
        room: await prepareHermesCleanRoom({
          ...cleanRoomOptions,
          hermesBinary: cleanHermesBinary,
          kitCommit: cleanKitCommit,
          kitUrl: cleanKitUrl,
          role: cleanRole,
          runRoot: cleanRunRoot,
        }),
        runRoot: cleanRunRoot,
      });
    }
    if (dryRun === true) {
      return Object.freeze({
        dryRun: true,
        manifests: Object.freeze(Object.fromEntries(ROLES.map((cleanRole) => [cleanRole, prepared[cleanRole].publicPreProvision]))),
        publicServices,
      });
    }
    phase = "credential";
    const credential = inferenceKeyValue !== undefined
      ? (() => {
          if (!SUPPORTED_INFERENCE_KEYS.includes(inferenceKeyName) || typeof inferenceKeyValue !== "string" || inferenceKeyValue.length === 0) fail();
          return { keyName: inferenceKeyName, value: inferenceKeyValue };
        })()
      : await readInferenceCredential({ credentialFile, env, keyName: inferenceKeyName ?? "MINIMAX_CN_API_KEY" });
    phase = "mint";
    const tokenEntries = [];
    for (const cleanRole of ROLES) {
      tokenEntries.push([cleanRole, validateToken(await mintDemoToken({ subject: `hermes-demo:${cleanRunId}:${cleanRole}` }))]);
    }
    const tokens = Object.fromEntries(tokenEntries);
    if (tokens.payer === tokens.requestor) fail();
    const tokenFingerprints = Object.freeze(Object.fromEntries(ROLES.map((cleanRole) => [cleanRole, tokenFingerprint(tokens[cleanRole])])));
    if (tokenFingerprints.payer === tokenFingerprints.requestor) fail();
    runtimeCanaries = Object.freeze([tokens.payer, tokens.requestor, credential.value]);
    evidenceCanaries = Object.freeze([...runtimeCanaries, cleanRunRoot]);
    phase = "provision";
    provisioned = {};
    for (const cleanRole of ROLES) {
      provisioned[cleanRole] = await validateProvisioned({
        keyName: credential.keyName,
        role: cleanRole,
        room: await provisionHermesCleanRoom({
          ...cleanRoomOptions,
          clockchainMcpToken: tokens[cleanRole],
          inferenceKeyName: credential.keyName,
          inferenceKeyValue: credential.value,
          peerClockchainMcpToken: tokens[cleanRole === "payer" ? "requestor" : "payer"],
          prepared: prepared[cleanRole],
          role: cleanRole,
        }),
        runRoot: cleanRunRoot,
        token: tokens[cleanRole],
      });
    }
    if (provisioned.payer.principalSha256 === provisioned.requestor.principalSha256) fail();
    for (const cleanRole of ROLES) {
      if (provisioned[cleanRole].principalSha256 !== tokenFingerprints[cleanRole]) fail();
    }
    cleanupState = { cleanRoom, keepCleanrooms, localDebug, provisioned, runRoot: cleanRunRoot };
    launch = {};
    for (const cleanRole of ROLES) {
      const prompt = buildHermesPrompt({ kitCommit: cleanKitCommit, kitUrl: cleanKitUrl, role: cleanRole });
      const usagePath = join(provisioned[cleanRole].paths.evidencePrivate, "usage.json");
      launch[cleanRole] = { prompt, promptSha256: sha256(prompt), usagePath };
      absolutePath(usagePath);
    }
    const controller = new AbortController();
    timeout = setTimeout(() => {
      agentTimedOut = true;
      controller.abort();
      for (const child of children) killChild(child);
    }, timeoutMs);
    const waiters = [];
    phase = "launch";
    for (const cleanRole of ROLES) {
      const child = spawnProcess(cleanHermesBinary, [
        "-z",
        launch[cleanRole].prompt,
        "--usage-file",
        launch[cleanRole].usagePath,
        "--ignore-rules",
        "--provider",
        "minimax-cn",
        "-m",
        "MiniMax-M3",
        "-t",
        "terminal,file,clockchain",
      ], {
        cwd: provisioned[cleanRole].paths.workspace,
        detached: true,
        env: provisioned[cleanRole].env,
        signal: controller.signal,
        stdio: ["ignore", "pipe", "pipe"],
      });
      children.push(child);
    }
    phase = "agents";
    for (const [index, cleanRole] of ROLES.entries()) {
      waiters.push(waitForChild({ canaries: runtimeCanaries, child: children[index], children, controller, role: cleanRole }));
    }
    const settled = await Promise.allSettled(waiters);
    childOutcomes = settled.map((entry, index) => entry.status === "fulfilled"
      ? entry.value
      : Object.freeze({
          diagnostic: childDiagnostic({ canaries: runtimeCanaries, reason: "waiter_error" }),
          ok: false,
          role: ROLES[index],
        }));
    const aborted = controller.signal.aborted;
    clearTimeout(timeout);
    timeout = null;
    if (aborted) {
      for (const child of children) killChild(child);
      fail();
    }
    if (childOutcomes.some((entry) => entry.ok !== true)) fail();
    const roleResults = Object.fromEntries(childOutcomes.map((entry) => [entry.role, entry.result]));
    const sessionId = roleResults.payer.sessionId;
    if (roleResults.requestor.sessionId !== sessionId) fail();
    phase = "relay";
    const relay = await verifyRelayResult({ relayUrl: relayUrl ?? DEFAULT_RELAY_URL, sessionId });
    const summary = validatedRelaySummary({ relay, roleResults });
    phase = "usage";
    const usages = {};
    for (const cleanRole of ROLES) {
      usages[cleanRole] = await readUsage(launch[cleanRole].usagePath, { terminalContractVerified: true });
    }
    phase = "post_run";
    const postRun = {};
    for (const cleanRole of ROLES) {
      postRun[cleanRole] = await inspectPostRun({
        commandRunner: postRunCommandRunner,
        kitCommit: cleanKitCommit,
        room: provisioned[cleanRole],
      });
    }
    phase = "cleanup";
    const cleanup = await safeCleanup(cleanupState);
    cleanupState = null;
    cleanupReport = cleanup;
    const evidence = Object.freeze({
      certificate: Object.freeze({
        digest: summary.certificateDigest,
        outcome: summary.outcome,
        paymentMoved: false,
        receipts: summary.receipts,
      }),
      cleanRooms: Object.freeze(Object.fromEntries(ROLES.map((cleanRole) => [cleanRole, Object.freeze({
        postRun: postRun[cleanRole],
        prePrompt: provisioned[cleanRole].publicPrePrompt,
        preProvision: provisioned[cleanRole].publicPreProvision,
      })]))),
      cleanup,
      finalResponses: roleResults,
      principals: Object.freeze({
        payer: Object.freeze({ sha256: provisioned.payer.principalSha256 }),
        requestor: Object.freeze({ sha256: provisioned.requestor.principalSha256 }),
      }),
      prompts: Object.freeze(Object.fromEntries(ROLES.map((cleanRole) => [cleanRole, Object.freeze({ sha256: launch[cleanRole].promptSha256 })]))),
      publicServices,
      runId: cleanRunId,
      summary,
      usage: usages,
    });
    const evidencePath = join(cleanRunRoot, "evidence", "result.json");
    phase = "evidence";
    await finalizeEvidence({ canaries: evidenceCanaries, evidence, evidencePath });
    return Object.freeze({ evidencePath, summary });
  } catch (error) {
    failureError = error;
    for (const cleanRole of ROLES) {
      const usagePath = launch?.[cleanRole]?.usagePath;
      failureUsages[cleanRole] = typeof usagePath === "string"
        ? await readFailureUsage(usagePath)
        : Object.freeze({ present: false });
    }
  } finally {
    if (timeout !== null) clearTimeout(timeout);
    for (const child of children) killChild(child);
    if (cleanupState !== null) {
      try {
        cleanupReport = await safeCleanup(cleanupState);
      } catch {
        // The retained failure artifact records the exact removal booleans.
      }
      cleanupState = null;
    }
    if (cleanRunRoot !== undefined && runRootReady === true) {
      cleanupReport = await cleanupSnapshot(cleanRunRoot).catch(() => cleanupReport);
    }
  }

  let checkpointEvidencePath = null;
  let failureEvidencePath = null;
  if (failureError !== null && cleanRunRoot !== undefined && cleanRunId !== undefined && runRootReady === true) {
    try {
      const checkpoint = failureCheckpoint({
        childOutcomes,
        cleanup: cleanupReport,
        phase,
        runId: cleanRunId,
        timedOut: agentTimedOut,
      });
      checkpointEvidencePath = join(cleanRunRoot, "evidence", "checkpoint.json");
      await finalizeEvidence({ canaries: evidenceCanaries, evidence: checkpoint, evidencePath: checkpointEvidencePath });
    } catch {
      checkpointEvidencePath = null;
    }
    try {
      const outcomes = Object.fromEntries(childOutcomes.map((entry) => [entry.role, entry]));
      const agents = Object.freeze(Object.fromEntries(ROLES.map((cleanRole) => {
        const outcome = outcomes[cleanRole];
        const diagnostic = outcome?.diagnostic ?? childDiagnostic({
          canaries: runtimeCanaries,
          reason: children.length > ROLES.indexOf(cleanRole) ? "no_result" : "not_started",
        });
        return [cleanRole, Object.freeze({
          ...diagnostic,
          usage: failureUsages[cleanRole] ?? Object.freeze({ present: false }),
        })];
      })));
      const cleanRooms = Object.freeze(Object.fromEntries(ROLES.map((cleanRole) => [cleanRole, Object.freeze({
        prePrompt: provisioned?.[cleanRole]?.publicPrePrompt ?? null,
        preProvision: prepared?.[cleanRole]?.publicPreProvision ?? null,
      })])));
      const evidence = Object.freeze({
        agents,
        cleanRooms,
        cleanup: cleanupReport ?? Object.freeze({ payerRemoved: false, requestorRemoved: false }),
        kitCommit: cleanKitCommit ?? null,
        paymentMoved: false,
        phase,
        prompts: Object.freeze(Object.fromEntries(ROLES.map((cleanRole) => [cleanRole, Object.freeze({
          sha256: launch?.[cleanRole]?.promptSha256 ?? null,
        })]))),
        publicServices,
        runId: cleanRunId,
        schema: "clockchain.hermes-demo-failure/v1",
        timedOut: agentTimedOut,
      });
      failureEvidencePath = join(cleanRunRoot, "evidence", "failure.json");
      await finalizeEvidence({ canaries: evidenceCanaries, evidence, evidencePath: failureEvidencePath });
    } catch {
      failureEvidencePath = null;
    }
  }
  const retainedFailurePath = failureEvidencePath ?? checkpointEvidencePath;
  if (retainedFailurePath !== null) {
    const error = new Error(SAFE_ERROR);
    Object.defineProperty(error, "failureEvidencePath", { value: retainedFailurePath });
    if (checkpointEvidencePath !== null) {
      Object.defineProperty(error, "checkpointEvidencePath", { value: checkpointEvidencePath });
    }
    throw error;
  }
  sanitize(failureError);
}

export const HERMES_DEMO_TERMINAL_MARKER = TERMINAL_MARKER;
export const HERMES_DEMO_DEFAULT_RELAY_URL = DEFAULT_RELAY_URL;
export const HERMES_DEMO_CANONICAL_KIT_URL = CANONICAL_KIT_URL;
