// clockchain-local-adapter — the pre-installed local half of the Clockchain
// agent handshake. The hosted coordinator (a stateless streamable-HTTP MCP
// endpoint) issues localAction objects whose helper steps must run LOCALLY:
// private keys never leave this machine and the server never signs. The
// portable fallback asks the model to download pinned helper bytes and run a
// multi-KB `node --eval` command; safety-conscious runtimes correctly refuse
// runtime download-and-execute. This adapter removes that path: the user
// installs it once, it proxies the handshake tools upstream so it can observe
// localActions flowing through tool responses, stages each returned helper
// step privately after validating it against the release pin, and exposes a
// single fixed zero-input tool — authorize_local_action — that executes one
// staged digest-bound step per call through the pinned local helper. No
// runtime download, no eval of remote bytes, no model transcription.
//
// Every failure is fail-closed with the same generic refusal: the adapter
// never distinguishes WHICH check a candidate step failed — with a single
// exception. A step that passes every structural check but is pinned to a
// different release digest is refused with the upgrade-directed
// ADAPTER_RELEASE_MISMATCH_REFUSAL instead, because "your adapter is behind"
// is actionable where a bare refusal is not.

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { tmpdir as osTmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import { createInterface } from "node:readline";
import { promisify, types } from "node:util";

import {
  AGENT_HANDSHAKE_HELPER_NODE_MAJOR,
  AGENT_HANDSHAKE_HELPER_VERSION,
  AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
} from "../agent-handshake/v2/constants.mjs";
import { localPolicyDigest, validateLocalPolicy } from "../agent-handshake/v2/policy.mjs";
import { canonicalBytes } from "../core/canonical.mjs";
import { VERIFIED_HELPER_BOOTSTRAP } from "../harness/verified-release-action-recorder.mjs";

const execFileAsync = promisify(execFile);

export const ADAPTER_NAME = "clockchain-local-adapter";
export const ADAPTER_TOOL = "authorize_local_action";
export const ADAPTER_APPROVAL_TOOL = `mcp__${ADAPTER_NAME}__${ADAPTER_TOOL}`;
export const ADAPTER_DEFAULT_ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
export const ADAPTER_ASSET_ERROR = "ADAPTER_ASSET_VERIFICATION_FAILED";

const CLI_RESULT_SCHEMA = "clockchain.agent-handshake-cli-result/v1";
const SIGNING_REQUEST_SCHEMA = "clockchain.agent-handshake-signing-request/v1";
const CERTIFICATE_VERIFICATION_SCHEMA = "clockchain.agent-handshake-certificate-verification/v1";
const HELPER_FILENAME = "clockchain-agent-handshake.cjs";
const MANIFEST_FILENAME = "manifest.json";
const PIN_FILENAME = "pin.json";
const TMPDIR_TOKEN = "${TMPDIR%/}";

const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const KID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const NODE_RUNTIME = new RegExp(`^${AGENT_HANDSHAKE_HELPER_NODE_MAJOR}\\.[0-9]+\\.[0-9]+$`);
const HELPER_ERROR_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;

// A structurally valid step pinned to a different release digest means the
// coordinator has moved to a helper release this adapter does not vendor —
// or the step is corrupt/forged. Fail closed either way, but unlike every
// other refusal this one names the recovery path.
export const ADAPTER_RELEASE_MISMATCH_REFUSAL =
  "clockchain-local-adapter is behind the coordinator's required helper " +
  "release — upgrade with: npx -y @clockchain/local-adapter@latest, then " +
  "restart your MCP client. If the adapter is already current, the step is " +
  "pinned to a different release — a mismatch that must not be bypassed.";
const GENERIC_REFUSAL = "Clockchain local adapter refused the action.";

const OPERATIONS = Object.freeze(["init", "policy", "inspect", "register", "sign", "verify-certificate"]);
const PAYLOAD_OPERATIONS = Object.freeze(["policy", "sign", "verify-certificate"]);
const SIGNING_OPERATIONS = Object.freeze(["identity_claim", "proposal", "acceptance", "evidence"]);
const ROLES = Object.freeze(["initiator", "responder"]);

const STEP_KEYS = Object.freeze([
  "operation", "role", "sessionId", "approvalTool", "commandLength",
  "commandSha256", "shellCommand", "shellCommandFetch", "policyDigest",
]);
const STEP_OPTIONAL_KEYS = Object.freeze(["shellCommandFetch", "policyDigest"]);
const PIN_KEYS = Object.freeze([
  "version", "sourceCommit", "manifestDigest", "allowedAssetPrefix", "hostRoots",
]);
const ROOT_KEYS = Object.freeze(["kid", "fingerprint"]);
const MANIFEST_KEYS = Object.freeze(["schema", "version", "sourceCommit", "nodeRuntime", "assets"]);
const ASSET_KEYS = Object.freeze([
  "platform", "arch", "upstreamSupport", "filename", "url", "byteLength",
  "sha256", "nativeSignature", "execution",
]);
const SIGNATURE_KEYS = Object.freeze(["type", "verified", "signer", "timestamp", "notarized"]);
const EXECUTION_KEYS = Object.freeze([
  "verified", "platform", "arch", "exitCode", "publicOutputSha256",
]);

// The coordinator's compactHelperStep emits exactly
//   <op> --state-dir "${TMPDIR%/}/.clockchain/handshakes/<uuid>/<role>"
// optionally followed by ` --payload-base64url <b64u>`; the quoted state-dir
// token is the only double-quoted word.
const SUFFIX_PATTERN = new RegExp(
  `^([a-z-]+) --state-dir "\\$\\{TMPDIR%/\\}/\\.clockchain/handshakes/` +
  `(${UUID.source.slice(1, -1)})/(initiator|responder)"` +
  `( --payload-base64url (${BASE64URL.source.slice(1, -1)}))?$`,
);

const MAX_STAGED_STEPS = 64;
const STAGED_STEP_TTL_MS = 20 * 60_000;
const UPSTREAM_RPC_BUDGET_MS = 30_000;
const HELPER_RUN_BUDGET_MS = 120_000;
const HELPER_MAX_OUTPUT_BYTES = 256 * 1024;
const MAX_LINE_BYTES = 1024 * 1024;
const MAX_PAYLOAD_BYTES = 512 * 1024;
const MAX_WALK_DEPTH = 32;
const FALLBACK_INSTRUCTIONS =
  "Clockchain local adapter: proxies the agent_handshake_* tools to the hosted " +
  "Clockchain coordinator and executes each staged, digest-bound local action " +
  "through the fixed zero-input tool authorize_local_action.";

const ADAPTER_TOOL_DEFINITION = Object.freeze({
  name: ADAPTER_TOOL,
  description:
    "Execute the next staged Clockchain local action for this role. The " +
    "adapter privately staged each digest-bound helper step issued inside a " +
    "localAction; one call executes exactly one staged step through the " +
    "pinned local helper. Takes no arguments; call once per staged step, in " +
    "order, waiting for each result before the next call.",
  inputSchema: Object.freeze({
    type: "object",
    properties: Object.freeze({}),
    additionalProperties: false,
  }),
});

function invalid() {
  throw new Error(GENERIC_REFUSAL);
}

function releaseMismatch() {
  throw new Error(ADAPTER_RELEASE_MISMATCH_REFUSAL);
}

function isPlain(value) {
  return (
    value !== null && typeof value === "object" && !Array.isArray(value) &&
    !types.isProxy(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value))
  );
}

function exact(value, keys, required = keys) {
  if (!isPlain(value)) invalid();
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string" || !keys.includes(key))) invalid();
  for (const key of required) if (!Object.hasOwn(value, key)) invalid();
  const result = {};
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) invalid();
    result[key] = descriptor.value;
  }
  return result;
}

// --- install-time asset gate ------------------------------------------------

function validatePin(value) {
  const item = exact(value, PIN_KEYS);
  if (
    item.version !== AGENT_HANDSHAKE_HELPER_VERSION ||
    !COMMIT.test(item.sourceCommit) || !SHA256.test(item.manifestDigest) ||
    item.allowedAssetPrefix !== AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX ||
    !Array.isArray(item.hostRoots) || item.hostRoots.length < 1 ||
    item.hostRoots.length > 2
  ) invalid();
  const roots = item.hostRoots.map((entry) => {
    const root = exact(entry, ROOT_KEYS);
    if (!KID.test(root.kid) || !SHA256.test(root.fingerprint)) invalid();
    return Object.freeze(root);
  });
  if (
    new Set(roots.map((root) => root.kid)).size !== roots.length ||
    new Set(roots.map((root) => root.fingerprint)).size !== roots.length
  ) invalid();
  return Object.freeze({ ...item, hostRoots: Object.freeze(roots) });
}

function validateManifestAsset(value, { allowedAssetPrefix, helperBytes }) {
  const item = exact(value, ASSET_KEYS);
  const signature = exact(item.nativeSignature, SIGNATURE_KEYS);
  const execution = exact(item.execution, EXECUTION_KEYS);
  if (
    item.platform !== "node" || item.arch !== "any" ||
    item.upstreamSupport !== "node24_portable" ||
    item.filename !== HELPER_FILENAME ||
    item.url !== `${allowedAssetPrefix}${HELPER_FILENAME}` ||
    !DECIMAL.test(item.byteLength) || BigInt(item.byteLength) < 1n ||
    !SHA256.test(item.sha256) ||
    signature.type !== "none" || signature.verified !== null ||
    signature.signer !== null || signature.timestamp !== null ||
    signature.notarized !== null ||
    execution.verified !== true || execution.platform !== "linux" ||
    execution.arch !== "x64" || execution.exitCode !== "0" ||
    !SHA256.test(execution.publicOutputSha256)
  ) invalid();
  if (
    String(helperBytes.length) !== item.byteLength ||
    createHash("sha256").update(helperBytes).digest("hex") !== item.sha256
  ) invalid();
  return Object.freeze(item);
}

export function verifyPinnedAssetBytes({ pin, manifestBytes, helperBytes } = {}) {
  const validatedPin = validatePin(pin);
  if (
    !Buffer.isBuffer(manifestBytes) || manifestBytes.length < 1 ||
    !Buffer.isBuffer(helperBytes) || helperBytes.length < 1 ||
    helperBytes.length > 1024 * 1024 ||
    createHash("sha256").update(manifestBytes).digest("hex") !== validatedPin.manifestDigest
  ) invalid();
  let manifest;
  try { manifest = JSON.parse(manifestBytes.toString("utf8")); } catch { invalid(); }
  const item = exact(manifest, MANIFEST_KEYS);
  if (
    item.schema !== "clockchain.agent-handshake-release-manifest/v1" ||
    item.version !== AGENT_HANDSHAKE_HELPER_VERSION ||
    item.sourceCommit !== validatedPin.sourceCommit ||
    !NODE_RUNTIME.test(item.nodeRuntime) ||
    !Array.isArray(item.assets) || item.assets.length !== 1
  ) invalid();
  try {
    if (!manifestBytes.equals(canonicalBytes(item))) invalid();
  } catch { invalid(); }
  validateManifestAsset(item.assets[0], {
    allowedAssetPrefix: validatedPin.allowedAssetPrefix,
    helperBytes,
  });
  return Object.freeze({
    helperBytes,
    helperSha256: item.assets[0].sha256,
    manifestBytes,
    pin: validatedPin,
  });
}

export function loadPinnedAssets({ assetDir, helperPath, manifestPath, pin, pinPath } = {}) {
  if (typeof assetDir !== "string" || !isAbsolute(resolve(assetDir))) invalid();
  const root = resolve(assetDir);
  const resolvedManifestPath = manifestPath !== undefined ? resolve(manifestPath) : join(root, MANIFEST_FILENAME);
  const resolvedHelperPath = helperPath !== undefined ? resolve(helperPath) : join(root, HELPER_FILENAME);
  const resolvedPinPath = pinPath !== undefined ? resolve(pinPath) : join(root, PIN_FILENAME);
  let pinValue = pin;
  if (pinValue === undefined) {
    try { pinValue = JSON.parse(readFileSync(resolvedPinPath, "utf8")); } catch { invalid(); }
  }
  let manifestBytes;
  let helperBytes;
  try {
    manifestBytes = readFileSync(resolvedManifestPath);
    helperBytes = readFileSync(resolvedHelperPath);
  } catch { invalid(); }
  const verified = verifyPinnedAssetBytes({ pin: pinValue, manifestBytes, helperBytes });
  return Object.freeze({
    ...verified,
    helperPath: resolvedHelperPath,
    manifestPath: resolvedManifestPath,
  });
}

// --- helper step validation --------------------------------------------------

function payloadBytes(encoded) {
  if (!BASE64URL.test(encoded)) invalid();
  const bytes = Buffer.from(encoded, "base64url");
  if (
    bytes.length < 1 || bytes.length > MAX_PAYLOAD_BYTES ||
    bytes.toString("base64url") !== encoded
  ) invalid();
  let record;
  try { record = JSON.parse(bytes.toString("utf8")); } catch { invalid(); }
  return record;
}

// Mirrors the requestBinding checks in the harness recorder, plus the
// coordinator-emitted schema/helperVersion binds the recorder leaves to the
// signed envelope.
function validatePayloadBinding(step, encoded) {
  const record = payloadBytes(encoded);
  if (!isPlain(record)) invalid();
  if (step.operation === "policy") {
    let policy;
    try { policy = validateLocalPolicy(record); } catch { invalid(); }
    if (policy.role !== step.role) invalid();
    if (step.policyDigest !== null && step.policyDigest !== localPolicyDigest(policy)) invalid();
    return;
  }
  if (
    (step.operation === "sign"
      ? record.schema !== SIGNING_REQUEST_SCHEMA || !SIGNING_OPERATIONS.includes(record.operation)
      : record.schema !== CERTIFICATE_VERIFICATION_SCHEMA) ||
    record.helperVersion !== AGENT_HANDSHAKE_HELPER_VERSION ||
    record.role !== step.role || record.sessionId !== step.sessionId ||
    record.externalBusinessActionPerformed !== false ||
    (step.policyDigest !== null && record.policyDigest !== step.policyDigest)
  ) invalid();
}

export function validateHelperStep(step, { manifestDigest } = {}) {
  if (!SHA256.test(manifestDigest)) invalid();
  const item = exact(
    step,
    STEP_KEYS,
    STEP_KEYS.filter((key) => !STEP_OPTIONAL_KEYS.includes(key)),
  );
  const shellCommand = item.shellCommand;
  if (typeof shellCommand !== "string" || shellCommand.length < 1) invalid();
  if (
    item.approvalTool !== ADAPTER_APPROVAL_TOOL ||
    !OPERATIONS.includes(item.operation) || !ROLES.includes(item.role) ||
    !UUID.test(item.sessionId) ||
    item.commandLength !== Buffer.byteLength(shellCommand) ||
    item.commandSha256 !== createHash("sha256").update(shellCommand).digest("hex") ||
    (item.shellCommandFetch !== undefined && typeof item.shellCommandFetch !== "string") ||
    (item.policyDigest !== undefined && !SHA256.test(item.policyDigest))
  ) invalid();
  const lead = `node --input-type=commonjs --eval '${VERIFIED_HELPER_BOOTSTRAP}' `;
  const assetArgs = ` ./${MANIFEST_FILENAME} ./${HELPER_FILENAME} `;
  if (!shellCommand.startsWith(lead)) invalid();
  const pinned = shellCommand.slice(lead.length);
  const stepDigest = pinned.slice(0, 64);
  if (!SHA256.test(stepDigest) || !pinned.slice(64).startsWith(assetArgs)) invalid();
  const suffix = pinned.slice(64 + assetArgs.length);
  const match = SUFFIX_PATTERN.exec(suffix);
  if (
    match === null || match[1] !== item.operation ||
    match[2] !== item.sessionId || match[3] !== item.role
  ) invalid();
  const encoded = match[5];
  if (PAYLOAD_OPERATIONS.includes(item.operation) !== (encoded !== undefined)) invalid();
  const staged = Object.freeze({
    commandLength: item.commandLength,
    commandSha256: item.commandSha256,
    operation: item.operation,
    payloadBase64url: encoded ?? null,
    policyDigest: item.policyDigest ?? null,
    role: item.role,
    sessionId: item.sessionId,
    stateDirShell: `${TMPDIR_TOKEN}/.clockchain/handshakes/${item.sessionId}/${item.role}`,
  });
  // policyDigest may bind only where the payload can carry it; an unverifiable
  // claim on a payload-less or digest-less step fails closed.
  if (staged.policyDigest !== null && !["policy", "sign"].includes(staged.operation)) invalid();
  // Every structural check has passed, so a differing embedded digest means
  // the step was minted against a different release pin — a different
  // manifestDigest, helper version, or allowedAssetPrefix all surface here.
  // Refuse as always, but with the distinct upgrade-directed text: it may be
  // an adapter that is behind, or a corrupt/forged step, and the message
  // covers both.
  if (stepDigest !== manifestDigest) releaseMismatch();
  if (encoded !== undefined) validatePayloadBinding(staged, encoded);
  return staged;
}

function collectHelperSteps(value, depth, out) {
  if (depth > MAX_WALK_DEPTH || value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const entry of value) collectHelperSteps(entry, depth + 1, out);
    return;
  }
  if (Object.hasOwn(value, "helperStep")) out.push(value.helperStep);
  if (Object.hasOwn(value, "helperSteps")) {
    if (!Array.isArray(value.helperSteps)) invalid();
    for (const entry of value.helperSteps) out.push(entry);
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key === "string") collectHelperSteps(value[key], depth + 1, out);
  }
}

// --- upstream proxy -----------------------------------------------------------

function parseUpstreamBody(text, contentType) {
  if (typeof text !== "string" || text.length === 0) invalid();
  if (!contentType?.includes("text/event-stream")) {
    try { return [JSON.parse(text)]; } catch { invalid(); }
  }
  // SSE: each blank-line-terminated event joins its data: lines with "\n".
  const messages = [];
  let data = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("data:")) {
      data = (data ?? "") + (data === null ? "" : "\n") + line.slice(5).replace(/^ /, "");
      continue;
    }
    if (line.trim() === "") {
      if (data !== null) { messages.push(data); data = null; }
    }
  }
  if (data !== null) messages.push(data);
  const parsed = [];
  for (const payload of messages) {
    try { parsed.push(JSON.parse(payload)); } catch { invalid(); }
  }
  return parsed;
}

// --- server --------------------------------------------------------------------

function helperErrorCode(stderr) {
  if (typeof stderr === "string" && stderr.trim().length > 0 && Buffer.byteLength(stderr) < 4096) {
    try {
      const parsed = JSON.parse(stderr.trim());
      const code = isPlain(parsed?.error) ? parsed.error.code : parsed?.code;
      if (typeof code === "string" && HELPER_ERROR_CODE.test(code)) return code;
    } catch { /* fall through to the generic refusal */ }
  }
  return "Clockchain local adapter refused the action.";
}

async function defaultRunHelper({ args, file, maxBufferBytes, timeoutMs }) {
  try {
    const { stdout, stderr } = await execFileAsync(file, args, {
      encoding: "utf8",
      env: process.env,
      maxBuffer: maxBufferBytes,
      timeout: timeoutMs,
    });
    return Object.freeze({
      code: 0,
      stderr: typeof stderr === "string" ? stderr : "",
      stdout: typeof stdout === "string" ? stdout : "",
    });
  } catch (error) {
    return Object.freeze({
      code: Number.isSafeInteger(error?.code) && error.code !== 0 ? error.code : 1,
      stderr: typeof error?.stderr === "string" ? error.stderr : "",
      stdout: typeof error?.stdout === "string" ? error.stdout : "",
    });
  }
}

export function createLocalAdapterServer(options = {}) {
  const input = exact(options, [
    "assetDir", "assets", "endpoint", "fetchImpl", "helperPath", "input",
    "manifestPath", "now", "output", "pin", "pinPath", "runHelper", "tmpdir",
  ], []);
  const assets = input.assets !== undefined
    ? (() => {
        const value = exact(input.assets, [
          "helperBytes", "helperPath", "helperSha256", "manifestBytes", "manifestPath", "pin",
        ]);
        if (
          !Buffer.isBuffer(value.helperBytes) || !Buffer.isBuffer(value.manifestBytes) ||
          typeof value.helperPath !== "string" || typeof value.manifestPath !== "string" ||
          !SHA256.test(value.helperSha256)
        ) invalid();
        return Object.freeze({ ...value, pin: validatePin(value.pin) });
      })()
    : loadPinnedAssets({
        assetDir: input.assetDir,
        helperPath: input.helperPath,
        manifestPath: input.manifestPath,
        pin: input.pin,
        pinPath: input.pinPath,
      });
  const pin = assets.pin;
  const endpoint = input.endpoint ??
    process.env.CLOCKCHAIN_LOCAL_ADAPTER_ENDPOINT ??
    ADAPTER_DEFAULT_ENDPOINT;
  if (typeof endpoint !== "string" || !/^https:\/\//.test(endpoint)) invalid();
  const fetchImpl = input.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") invalid();
  const runHelper = input.runHelper ?? defaultRunHelper;
  if (typeof runHelper !== "function") invalid();
  if (input.now !== undefined && typeof input.now !== "function") invalid();
  if (input.tmpdir !== undefined && typeof input.tmpdir !== "string") invalid();
  const now = input.now ?? Date.now;
  const tmpRoot = resolve(input.tmpdir ?? process.env.TMPDIR ?? osTmpdir());
  const queue = [];
  let upstreamId = 0;
  let upstreamInit = null;
  let pendingExecution = Promise.resolve();

  async function upstreamRequest(method, params, { notification = false } = {}) {
    const id = ++upstreamId;
    const body = notification
      ? { jsonrpc: "2.0", method, ...(params !== undefined ? { params } : {}) }
      : { jsonrpc: "2.0", id, method, ...(params !== undefined ? { params } : {}) };
    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json, text/event-stream",
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(UPSTREAM_RPC_BUDGET_MS),
    });
    if (!response?.ok) invalid();
    const text = await response.text();
    if (notification) return null;
    const messages = parseUpstreamBody(text, response.headers?.get?.("content-type") ?? "");
    const envelope = messages.find((message) => isPlain(message) && message.id === id);
    if (
      envelope === undefined || envelope.jsonrpc !== "2.0" ||
      (envelope.result === undefined) === (envelope.error === undefined)
    ) invalid();
    return envelope;
  }

  function upstreamInitialize(params) {
    if (upstreamInit === null) {
      upstreamInit = upstreamRequest("initialize", params ?? {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: ADAPTER_NAME, version: pin.version },
      }).then((envelope) => {
        if (envelope.error !== undefined) return null;
        // Best-effort session notification; the endpoint is stateless, so a
        // failure here must not poison the cached initialize result.
        void upstreamRequest("notifications/initialized", {}, { notification: true }).catch(() => {});
        return isPlain(envelope.result) ? envelope.result : null;
      }).catch(() => null);
    }
    return upstreamInit;
  }

  function stageToolResult(result) {
    if (!isPlain(result) || !Array.isArray(result.content)) return;
    const candidates = [];
    for (const item of result.content) {
      if (!isPlain(item) || item.type !== "text" || typeof item.text !== "string") continue;
      let parsed;
      try { parsed = JSON.parse(item.text); } catch { continue; }
      collectHelperSteps(parsed, 0, candidates);
    }
    for (const candidate of candidates) {
      const staged = validateHelperStep(candidate, { manifestDigest: pin.manifestDigest });
      // The coordinator re-issues an unchanged localAction on each poll while a
      // step stays pending — the same byte-identical command is the same
      // digest-bound action, so an already-staged duplicate must not shift the
      // queue head away from the step the caller just read.
      if (queue.some((pending) => pending.commandSha256 === staged.commandSha256)) continue;
      if (queue.length >= MAX_STAGED_STEPS) invalid();
      queue.push(Object.freeze({ ...staged, stagedAtMs: now() }));
    }
  }

  function textResult(text, isError = false) {
    return Object.freeze({
      content: Object.freeze([Object.freeze({ type: "text", text })]),
      ...(isError ? { isError: true } : {}),
    });
  }

  function resolveStateDir(step) {
    if (!step.stateDirShell.startsWith(`${TMPDIR_TOKEN}/`)) invalid();
    const stateDir = resolve(tmpRoot + step.stateDirShell.slice(TMPDIR_TOKEN.length));
    const offset = relative(tmpRoot, stateDir);
    if (
      offset === "" || offset.startsWith("..") || isAbsolute(offset) ||
      !stateDir.endsWith(`/.clockchain/handshakes/${step.sessionId}/${step.role}`)
    ) invalid();
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    return stateDir;
  }

  // Tool-call-time re-verification: the spawned bootstrap re-checks both
  // digests inside the child, so this gate exists to refuse before spawn.
  function verifyAssetsNow() {
    let manifestBytes;
    let helperBytes;
    try {
      manifestBytes = readFileSync(assets.manifestPath);
      helperBytes = readFileSync(assets.helperPath);
    } catch { invalid(); }
    if (
      createHash("sha256").update(manifestBytes).digest("hex") !== pin.manifestDigest ||
      createHash("sha256").update(helperBytes).digest("hex") !== assets.helperSha256
    ) invalid();
  }

  async function executeStagedAction() {
    while (queue.length > 0 && now() - queue[0].stagedAtMs > STAGED_STEP_TTL_MS) queue.shift();
    const step = queue.shift();
    if (step === undefined) {
      return textResult("Clockchain local adapter has no staged action to execute.", true);
    }
    verifyAssetsNow();
    const stateDir = resolveStateDir(step);
    const args = [
      "--input-type=commonjs", "--eval", VERIFIED_HELPER_BOOTSTRAP,
      pin.manifestDigest, assets.manifestPath, assets.helperPath,
      step.operation, "--state-dir", stateDir,
    ];
    if (step.payloadBase64url !== null) args.push("--payload-base64url", step.payloadBase64url);
    const outcome = await runHelper({
      args: Object.freeze(args),
      // The helper must run under real Node >=24. process.execPath is that
      // Node under the stdio entry; under a compiled binary (e.g. bun) it is
      // the adapter itself, so an explicit override exists.
      file: process.env.CLOCKCHAIN_LOCAL_ADAPTER_NODE ?? process.execPath,
      maxBufferBytes: HELPER_MAX_OUTPUT_BYTES,
      timeoutMs: HELPER_RUN_BUDGET_MS,
    });
    if (!isPlain(outcome) || outcome.code !== 0) {
      return textResult(helperErrorCode(outcome?.stderr), true);
    }
    const text = typeof outcome.stdout === "string" ? outcome.stdout.trim() : "";
    if (text.length < 2 || text.length > HELPER_MAX_OUTPUT_BYTES) invalid();
    let record;
    try { record = JSON.parse(text); } catch { invalid(); }
    if (
      !isPlain(record) || record.schema !== CLI_RESULT_SCHEMA ||
      record.helperVersion !== pin.version || record.operation !== step.operation
    ) invalid();
    return textResult(text);
  }

  async function callAdapterTool(params) {
    if (!isPlain(params)) return { error: { code: -32602, message: "invalid params" } };
    const args = params.arguments;
    if (
      args !== undefined &&
      (!isPlain(args) || Reflect.ownKeys(args).length !== 0)
    ) return { error: { code: -32602, message: "tool takes no arguments" } };
    // Serialize executions: a second call while one is in flight must see the
    // queue state the first execution left behind, never a shared head.
    const run = pendingExecution.then(() => executeStagedAction());
    pendingExecution = run.catch(() => {});
    try {
      return { result: await run };
    } catch {
      return { result: textResult(GENERIC_REFUSAL, true) };
    }
  }

  async function handleToolsList(id, params) {
    try {
      const envelope = await upstreamRequest("tools/list", params);
      if (envelope.error !== undefined) return { jsonrpc: "2.0", id, error: envelope.error };
      const result = isPlain(envelope.result) ? envelope.result : {};
      const tools = Array.isArray(result.tools) ? result.tools : [];
      return {
        jsonrpc: "2.0",
        id,
        result: { ...result, tools: [...tools, ADAPTER_TOOL_DEFINITION] },
      };
    } catch {
      // An unreachable coordinator must not hide the one tool that is local.
      return {
        jsonrpc: "2.0",
        id,
        result: { tools: [ADAPTER_TOOL_DEFINITION] },
      };
    }
  }

  async function handleToolsCall(id, params) {
    if (!isPlain(params) || typeof params.name !== "string") {
      return { jsonrpc: "2.0", id, error: { code: -32602, message: "invalid params" } };
    }
    if (params.name === ADAPTER_TOOL) {
      const outcome = await callAdapterTool(params);
      return { jsonrpc: "2.0", id, ...outcome };
    }
    let envelope;
    try {
      envelope = await upstreamRequest("tools/call", params);
    } catch {
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: "Clockchain local adapter upstream request failed." },
      };
    }
    if (envelope.error !== undefined) return { jsonrpc: "2.0", id, error: envelope.error };
    try {
      stageToolResult(envelope.result);
    } catch (error) {
      // The only refusal text allowed past this boundary besides the generic
      // one is the release-mismatch upgrade hint — arbitrary error messages
      // never leak upstream internals.
      const text =
        typeof error?.message === "string" && error.message === ADAPTER_RELEASE_MISMATCH_REFUSAL
          ? ADAPTER_RELEASE_MISMATCH_REFUSAL
          : GENERIC_REFUSAL;
      return {
        jsonrpc: "2.0",
        id,
        result: textResult(text, true),
      };
    }
    return { jsonrpc: "2.0", id, result: envelope.result };
  }

  async function handleInitialize(id, params) {
    const requested = isPlain(params) && typeof params.protocolVersion === "string"
      ? params.protocolVersion
      : null;
    const upstream = await upstreamInitialize(isPlain(params) ? params : undefined);
    const upstreamProtocol = typeof upstream?.protocolVersion === "string"
      ? upstream.protocolVersion
      : null;
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: requested ?? upstreamProtocol ?? "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: ADAPTER_NAME, version: pin.version },
        instructions: typeof upstream?.instructions === "string"
          ? upstream.instructions
          : FALLBACK_INSTRUCTIONS,
      },
    };
  }

  async function handleMessage(message) {
    if (!isPlain(message) || message.jsonrpc !== "2.0") return null;
    const method = message.method;
    if (typeof method !== "string") return null;
    if (method.startsWith("notifications/")) return null;
    const id = message.id;
    if (id === undefined || id === null) return null;
    if (method === "initialize") return handleInitialize(id, message.params);
    if (method === "ping") return { jsonrpc: "2.0", id, result: {} };
    if (method === "tools/list") return handleToolsList(id, message.params);
    if (method === "tools/call") return handleToolsCall(id, message.params);
    return { jsonrpc: "2.0", id, error: { code: -32601, message: "method not found" } };
  }

  return Object.freeze({
    handleMessage,
    pendingCount: () => queue.length,
    pin,
    serverInfo: Object.freeze({ name: ADAPTER_NAME, version: pin.version }),
    toolDefinition: ADAPTER_TOOL_DEFINITION,
  });
}

export function startLocalAdapterStdio(options = {}) {
  const server = createLocalAdapterServer(options);
  const input = options?.input ?? process.stdin;
  const output = options?.output ?? process.stdout;
  // A closed stdout (client exited mid-session) must not crash the loop.
  output.on?.("error", () => {});
  const lines = createInterface({ input, terminal: false });
  lines.on("line", (line) => {
    if (line.trim().length === 0 || Buffer.byteLength(line) > MAX_LINE_BYTES) return;
    let message;
    try { message = JSON.parse(line); } catch { return; }
    void Promise.resolve(server.handleMessage(message))
      .then((response) => {
        if (response !== null && response !== undefined) {
          output.write(`${JSON.stringify(response)}\n`);
        }
      })
      .catch(() => {});
  });
  return Object.freeze({
    server,
    close() { lines.close(); },
  });
}
