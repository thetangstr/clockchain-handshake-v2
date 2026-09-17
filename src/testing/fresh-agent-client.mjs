import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join, relative, resolve } from "node:path";

import { assertSecretFree } from "../core/redact.mjs";
import { validateAgentHandshakeReleasePin } from "../../scripts/verify-agent-handshake-release.mjs";
import {
  createCheckpointCompletionHandler,
  createStreamableMcpClient,
  ROLE_ACCESS_HANDLE,
  roleAccessBinding,
} from "../harness/checkpoint-completion.mjs";
import { createVerifiedReleaseActionRecorder, VERIFIED_HELPER_BOOTSTRAP } from "../harness/verified-release-action-recorder.mjs";
import { AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX } from "../agent-handshake/v2/constants.mjs";

const ROLES = Object.freeze(["initiator", "responder"]);
const HELPER_OPERATIONS = Object.freeze([
  "init", "policy", "inspect", "register", "sign", "verify-certificate",
]);
const RELEASE_PREFIX = AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX;

export const CLOCKCHAIN_HANDSHAKE_MCP_URL = "https://mcp.clockchain.network/handshake/mcp";
export const FRESH_AGENT_CLIENTS = Object.freeze(["codex", "claude"]);
export const CLOCKCHAIN_HANDSHAKE_TOOLS = Object.freeze([
  "agent_handshake_invite",
  "agent_handshake_accept_invitation",
  "agent_handshake_join",
  "agent_handshake_status",
  "agent_handshake_next",
  "agent_handshake_submit_checkpoint",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);
export { VERIFIED_HELPER_BOOTSTRAP };

const SAFE_SEGMENT = /^[A-Za-z0-9._-]+$/;
const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const TX = /^0x[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const ROLE_TOKEN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const UNSAFE_SHELL = /[\0\r\n;&|`$<>]/;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const TERMINAL_SCHEMA = "clockchain.fresh-agent-terminal-proof/v1";
const EVIDENCE_SCHEMA = "clockchain.fresh-agent-canary-evidence/v1";
const RESPONDER_INVITATION_PLACEHOLDER = "<PASTE THE INITIATOR INVITATION>";
// Substituted with a randomUUID() at send time so the model never invents an
// acceptanceIdempotencyKey that fails server validation inside the short
// invitation window.
const RESPONDER_ACCEPTANCE_KEY_PLACEHOLDER = "<GENERATED ACCEPTANCE IDEMPOTENCY KEY>";

function fail() {
  throw new Error("Fresh agent compatibility check failed safely.");
}

function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  const actual = Object.keys(value).sort();
  if (JSON.stringify(actual) !== JSON.stringify([...keys].sort())) fail();
  return value;
}

function cleanClient(value) {
  if (!FRESH_AGENT_CLIENTS.includes(value)) fail();
  return value;
}

function cleanRole(value) {
  if (!ROLES.includes(value)) fail();
  return value;
}

function absolute(value) {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value || value.includes("\0")) fail();
  return value;
}

function descendant(root, value) {
  const cleanRoot = absolute(root);
  const cleanValue = absolute(value);
  const offset = relative(cleanRoot, cleanValue);
  if (offset === "" || offset.startsWith("..") || isAbsolute(offset)) fail();
  return cleanValue;
}

function safeArg(value) {
  if (typeof value !== "string" || value.length === 0 || UNSAFE_SHELL.test(value)) fail();
  return value;
}

function validateRoots(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 2 || value.some((entry) => !SHA256.test(entry))) fail();
  const roots = [...value].sort();
  if (new Set(roots).size !== roots.length) fail();
  return roots;
}

export function validateReleaseAgreement(value) {
  const input = exactObject(value, ["mcp", "research"]);
  const mcp = exactObject(input.mcp, ["hostRoots", "manifestDigest"]);
  const research = exactObject(input.research, ["hostRoots", "manifestDigest"]);
  if (!SHA256.test(mcp.manifestDigest) || mcp.manifestDigest !== research.manifestDigest) fail();
  const left = validateRoots(mcp.hostRoots);
  const right = validateRoots(research.hostRoots);
  if (JSON.stringify(left) !== JSON.stringify(right)) fail();
  return Object.freeze({ manifestDigest: mcp.manifestDigest, hostRoots: Object.freeze(left) });
}

function validateAssetUrl(value) {
  const raw = safeArg(value);
  if (!raw.startsWith(RELEASE_PREFIX)) fail();
  let url;
  try { url = new URL(raw); } catch { fail(); }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") fail();
  if (url.origin !== "https://github.com" || !raw.startsWith(RELEASE_PREFIX)) fail();
  const asset = raw.slice(RELEASE_PREFIX.length);
  if (!["manifest.json", "clockchain-agent-handshake.cjs"].includes(asset)) fail();
  return Object.freeze({ asset, url: raw });
}

const RELEASE_REDIRECT_HOST = /(^|\.)githubusercontent\.com$/;

async function defaultFetchReleaseAsset(url) {
  let current = url;
  for (let hop = 0; hop < 6; hop += 1) {
    const response = await fetch(current, { redirect: "manual", signal: AbortSignal.timeout(30_000) });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      try { await response.body?.cancel(); } catch { /* discard redirect body */ }
      let next;
      try { next = new URL(location ?? "", current); } catch { fail(); }
      if (next.protocol !== "https:" || (next.hostname !== "github.com" && !RELEASE_REDIRECT_HOST.test(next.hostname))) fail();
      current = next.href;
      continue;
    }
    if (!response.ok) fail();
    return Buffer.from(await response.arrayBuffer());
  }
  fail();
}

async function loadReleasePin() {
  try {
    return JSON.parse(await readFile(new URL("../../release/agent-handshake/pin.json", import.meta.url), "utf8"));
  } catch { fail(); }
}

async function fetchVerifiedReleaseAssets(agreement, releasePin, fetchAsset) {
  const [manifestBytes, helperBytes] = (await Promise.all([
    fetchAsset(validateAssetUrl(`${RELEASE_PREFIX}manifest.json`).url),
    fetchAsset(validateAssetUrl(`${RELEASE_PREFIX}clockchain-agent-handshake.cjs`).url),
  ])).map((bytes) => Buffer.from(bytes));
  try {
    validateAgentHandshakeReleasePin(releasePin, { manifestBytes, helperBytes });
  } catch { fail(); }
  const fingerprints = releasePin.hostRoots.map((root) => root.fingerprint).sort();
  if (releasePin.manifestDigest !== agreement.manifestDigest || JSON.stringify(fingerprints) !== JSON.stringify(agreement.hostRoots)) fail();
  return Object.freeze({ helperBytes, manifestBytes });
}

// The adapter boundary is the only local authority a model needs: signed helper
// actions are executed through the digest-bound executable the harness places on
// PATH, and the pinned release bytes are preloaded for inspection. Downloads and
// direct helper invocations are intentionally not granted.
function claudeAdapterTools() {
  return Object.freeze([
    "Bash(clockchain-agent-authorize *)",
    "Read(./manifest.json)",
    "Read(./clockchain-agent-handshake.cjs)",
  ]);
}

function validateHelperArgv(argv, workspace, manifestDigest) {
  if (!Array.isArray(argv) || argv.length < 8 || argv.some((entry) => typeof entry !== "string")) fail();
  argv.forEach((entry, index) => { if (index !== 3) safeArg(entry); });
  if (
    argv[0] !== "node" || argv[1] !== "--input-type=commonjs" || argv[2] !== "--eval" ||
    argv[3] !== VERIFIED_HELPER_BOOTSTRAP || argv[4] !== manifestDigest || !SHA256.test(manifestDigest)
  ) fail();
  const manifestPath = descendant(workspace, argv[5]);
  const helperPath = descendant(workspace, argv[6]);
  if (basename(manifestPath) !== "manifest.json" || basename(helperPath) !== "clockchain-agent-handshake.cjs") fail();
  if (argv[7] === "--version" && argv.length === 8) return;
  if (!HELPER_OPERATIONS.includes(argv[7]) || argv[8] !== "--state-dir") fail();
  descendant(workspace, argv[9]);
  if (argv.length === 10) return;
  if (argv.length !== 12 || argv[10] !== "--payload-base64url" || !BASE64URL.test(argv[11])) fail();
}

export function validateHelperCommand({ argv, kind, manifestDigest, workspace } = {}) {
  const cleanWorkspace = absolute(workspace);
  if (!Array.isArray(argv)) fail();
  if (kind === "download") {
    if (
      argv.length !== 8 || argv[0] !== "curl" || argv[1] !== "--fail" ||
      argv[2] !== "--location" || argv[3] !== "--proto" || argv[4] !== "=https" ||
      argv[5] !== "--output"
    ) fail();
    argv.forEach(safeArg);
    const output = descendant(cleanWorkspace, argv[6]);
    const download = validateAssetUrl(argv[7]);
    if (basename(output) !== download.asset) fail();
    return true;
  }
  if (kind === "helper") {
    validateHelperArgv(argv, cleanWorkspace, manifestDigest);
    return true;
  }
  fail();
}

export function buildClientCommands({ client, manifestDigest, prompt, workspace } = {}) {
  const clean = cleanClient(client);
  const cwd = absolute(workspace);
  if (!SHA256.test(manifestDigest)) fail();
  if (typeof prompt !== "string" || prompt.length === 0) fail();
  if (clean === "codex") {
    return Object.freeze({
      configure: Object.freeze({
        args: Object.freeze(["mcp", "add", "clockchain-handshake", "--url", CLOCKCHAIN_HANDSHAKE_MCP_URL]),
        file: "codex",
      }),
      launch: Object.freeze({
        args: Object.freeze([
          "exec", "--skip-git-repo-check", "--strict-config", "--ignore-rules", "--ephemeral",
          "--sandbox", "workspace-write", "--config", 'approval_policy="never"',
          "--config", "sandbox_workspace_write.network_access=true", "--json", "--cd", cwd, "-",
        ]),
        file: "codex",
        input: prompt,
        limitation: "Codex workspace-write does not provide literal command-pattern enforcement.",
      }),
    });
  }
  return Object.freeze({
    configure: Object.freeze({
      args: Object.freeze(["mcp", "add", "--transport", "http", "--scope", "user", "clockchain-handshake", CLOCKCHAIN_HANDSHAKE_MCP_URL]),
      file: "claude",
    }),
    launch: Object.freeze({
      args: Object.freeze([
        "--print", "--bare", "--disable-slash-commands", "--no-chrome",
        "--strict-mcp-config", "--mcp-config", JSON.stringify({
          mcpServers: { "clockchain-handshake": { type: "http", url: CLOCKCHAIN_HANDSHAKE_MCP_URL } },
        }),
        "--permission-mode", "dontAsk",
        "--no-session-persistence",
        "--setting-sources", "",
        "--output-format", "stream-json",
        "--verbose",
        "--allowedTools", CLOCKCHAIN_HANDSHAKE_TOOLS
          .map((tool) => `mcp__clockchain-handshake__${tool}`)
          .concat(claudeAdapterTools())
          .join(","),
      ]),
      file: "claude",
      input: prompt,
      limitation: null,
    }),
  });
}

async function privateDirectory(path) {
  await mkdir(path, { recursive: false, mode: 0o700 });
  if (process.platform !== "win32") await chmod(path, 0o700);
}

export async function createFreshAgentRun({ parent, runId = randomUUID() } = {}) {
  const cleanParent = await realpath(absolute(parent));
  if (typeof runId !== "string" || !SAFE_SEGMENT.test(runId)) fail();
  const root = join(cleanParent, runId);
  await privateDirectory(root);
  const rolesRoot = join(root, "roles");
  await privateDirectory(rolesRoot);
  const roles = {};
  for (const role of ROLES) {
    const roleRoot = join(rolesRoot, role);
    await privateDirectory(roleRoot);
    const entry = { root: roleRoot };
    for (const name of ["home", "workspace", "cache", "state", "tmp"]) {
      entry[name] = join(roleRoot, name);
      await privateDirectory(entry[name]);
    }
    roles[role] = Object.freeze(entry);
  }
  return Object.freeze({ root, roles: Object.freeze(roles), runId });
}

function append(output, chunk) {
  const next = output + Buffer.from(chunk).toString("utf8");
  if (Buffer.byteLength(next) > MAX_OUTPUT_BYTES) fail();
  return next;
}

function validateTerminal(parsed, role) {
  exactObject(parsed, [
    "schema", "role", "sessionId", "policyDigest", "address", "erc8004",
    "receiptIds", "certificateDigest", "certificateVerified", "externalBusinessActionPerformed",
  ]);
  if (
    parsed.schema !== TERMINAL_SCHEMA || parsed.role !== role || !UUID.test(parsed.sessionId) ||
    !SHA256.test(parsed.policyDigest) || !ADDRESS.test(parsed.address) || !SHA256.test(parsed.certificateDigest) ||
    parsed.certificateVerified !== true || parsed.externalBusinessActionPerformed !== false
  ) fail();
  const identity = exactObject(parsed.erc8004, ["agentId", "reference", "registrationTx", "registrationBlock"]);
  if (!DECIMAL.test(identity.agentId) || !DECIMAL.test(identity.registrationBlock) || !TX.test(identity.registrationTx)) fail();
  if (typeof identity.reference !== "string" || !identity.reference.endsWith(`:${identity.agentId}`)) fail();
  if (!Array.isArray(parsed.receiptIds) || parsed.receiptIds.length !== 3 || new Set(parsed.receiptIds).size !== 3) fail();
  if (parsed.receiptIds.some((entry) => typeof entry !== "string" || entry.length === 0)) fail();
  return Object.freeze({ ...parsed, erc8004: Object.freeze({ ...identity }), receiptIds: Object.freeze([...parsed.receiptIds]) });
}

function invitation(value) {
  if (typeof value !== "string" || value.length < 80 || value.length > 4096 || !ROLE_TOKEN.test(value)) fail();
  return value;
}

function parseJsonString(value) {
  const clean = value.trim();
  const fenced = /^```json\r?\n(\{[\s\S]*\})\r?\n```$/u.exec(clean);
  const candidate = fenced?.[1] ?? clean;
  if (!candidate.startsWith("{") || !candidate.endsWith("}")) return null;
  try { return JSON.parse(candidate); } catch { return null; }
}

function inspectEvent(value, role, depth = 0) {
  if (depth > 12) fail();
  if (typeof value === "string") {
    const parsed = parseJsonString(value);
    return parsed === null ? {} : inspectEvent(parsed, role, depth + 1);
  }
  if (value === null || typeof value !== "object") return {};
  if (Array.isArray(value)) {
    return value.reduce((found, entry) => mergeObserved(found, inspectEvent(entry, role, depth + 1)), {});
  }
  let found = {};
  if (Object.hasOwn(value, "responderInvitation")) {
    found = { invitation: invitation(value.responderInvitation) };
  }
  if (value.schema === TERMINAL_SCHEMA) {
    found = mergeObserved(found, { terminal: validateTerminal(value, role) });
  }
  for (const entry of Object.values(value)) {
    found = mergeObserved(found, inspectEvent(entry, role, depth + 1));
  }
  return found;
}

function mergeObserved(left, right) {
  const merged = { ...left };
  for (const key of ["invitation", "terminal"]) {
    if (right[key] === undefined) continue;
    if (merged[key] !== undefined && JSON.stringify(merged[key]) !== JSON.stringify(right[key])) fail();
    merged[key] = right[key];
  }
  return merged;
}

// Walks a streamed client event (objects, arrays, and JSON-bearing strings) and
// returns every localAction helper step the endpoint made visible to the model.
// Presence is enough — the adapter re-validates each step before retaining it.
function collectHelperSteps(value, found = [], depth = 0) {
  if (depth > 12) fail();
  if (typeof value === "string") {
    const parsed = parseJsonString(value);
    if (parsed !== null) collectHelperSteps(parsed, found, depth + 1);
    return found;
  }
  if (value === null || typeof value !== "object") return found;
  if (Array.isArray(value)) {
    for (const entry of value) collectHelperSteps(entry, found, depth + 1);
    return found;
  }
  const localAction = value.localAction;
  if (localAction !== null && typeof localAction === "object" && !Array.isArray(localAction)) {
    if (localAction.helperStep !== undefined && localAction.helperStep !== null) {
      found.push(localAction.helperStep);
    }
    if (localAction.helperSteps !== undefined) {
      if (!Array.isArray(localAction.helperSteps)) fail();
      for (const step of localAction.helperSteps) {
        if (step !== null) found.push(step);
      }
    }
  }
  for (const entry of Object.values(value)) {
    collectHelperSteps(entry, found, depth + 1);
  }
  return found;
}

function isClockchainMcpToolName(value) {
  return typeof value === "string" && CLOCKCHAIN_HANDSHAKE_TOOLS.some(
    (name) => value === name || value.endsWith(`__${name}`),
  );
}

function mcpToolName(item) {
  const value = item?.tool ?? item?.name;
  return isClockchainMcpToolName(value) ? value : null;
}

export function recordClaudeMcpToolCalls(event, calls) {
  if (event?.type !== "assistant" || !Array.isArray(event?.message?.content)) return;
  for (const block of event.message.content) {
    if (
      block?.type === "tool_use" && typeof block.id === "string" && block.id.length > 0 &&
      isClockchainMcpToolName(block.name)
    ) {
      calls.set(block.id, CLOCKCHAIN_HANDSHAKE_TOOLS.find((name) => (
        block.name === name || block.name.endsWith(`__${name}`)
      )));
    }
  }
}

// Finds the role access value inside a completed MCP tool result: either an
// opaque ccra_ handle paired with a sessionId sibling, or a <claims>.<sig>
// token whose embedded role/sessionId claims are decoded and verified.
export function roleAccessFromValue(value, expectedRole) {
  const pending = [value];
  let found = null;
  let visited = 0;
  while (pending.length > 0) {
    if (++visited > 10_000) fail();
    const current = pending.pop();
    if (typeof current === "string") {
      const parsed = parseJsonString(current);
      if (parsed !== null) pending.push(parsed);
      continue;
    }
    if (current === null || typeof current !== "object") continue;
    if (Array.isArray(current)) {
      pending.push(...current);
      continue;
    }
    if (Object.hasOwn(current, "roleAccess")) {
      let binding;
      if (typeof current.roleAccess === "string" && ROLE_TOKEN.test(current.roleAccess)) {
        binding = roleAccessBinding(current.roleAccess);
        if (Object.hasOwn(current, "sessionId") && current.sessionId !== binding.sessionId) fail();
      } else {
        binding = Object.hasOwn(current, "sessionId")
          ? roleAccessBinding({
              access: current.roleAccess,
              role: expectedRole,
              sessionId: current.sessionId,
            })
          : roleAccessBinding(current.roleAccess);
      }
      if (typeof binding !== "string" && binding.role !== expectedRole) fail();
      if (found !== null) {
        const foundAccess = typeof found === "string" ? found : found.access;
        const bindingAccess = typeof binding === "string" ? binding : binding.access;
        if (foundAccess !== bindingAccess) fail();
        if (typeof found !== "string" && typeof binding !== "string" &&
            JSON.stringify(found) !== JSON.stringify(binding)) fail();
      }
      if (found === null || (typeof found === "string" && typeof binding !== "string")) found = binding;
    }
    pending.push(...Object.values(current));
  }
  return found;
}

// Values the model could not have authored: Codex completed mcp_tool_call
// results on a Clockchain tool, and Claude tool_result blocks whose
// tool_use_id was recorded from an assistant tool_use naming a Clockchain MCP
// tool. Only these values may yield helper steps or role access — generic
// assistant/user text carrying a look-alike localAction is never trusted.
function completedMcpToolResults(event, claudeMcpToolCalls) {
  const values = [];
  if (
    event?.type === "item.completed" && event?.item?.type === "mcp_tool_call" &&
    event.item.status === "completed" && mcpToolName(event.item) !== null
  ) values.push(event.item.result);
  if (event?.type === "user" && Array.isArray(event?.message?.content)) {
    for (const block of event.message.content) {
      if (
        block?.type === "tool_result" && block.is_error !== true &&
        typeof block.tool_use_id === "string" && claudeMcpToolCalls.has(block.tool_use_id)
      ) values.push(block.content);
    }
  }
  return values;
}

export function bindCompletedRoleAccess(event, claudeMcpToolCalls, adapter, expectedRole) {
  for (const value of completedMcpToolResults(event, claudeMcpToolCalls)) {
    const access = roleAccessFromValue(value, expectedRole);
    if (access === null) continue;
    adapter.bindRoleAccess(access);
  }
}

function killProcessGroup(child) {
  if (!child || child.__freshAgentClosed === true) return;
  child.__freshAgentClosed = true;
  try {
    if (Number.isSafeInteger(child.pid) && child.pid > 0) process.kill(-child.pid, "SIGTERM");
    else child.kill?.("SIGTERM");
  } catch { child.kill?.("SIGTERM"); }
}

function observeChild(child, role, all, canaries, { adapter, requireInvitation = false } = {}) {
  if (
    adapter === null || typeof adapter !== "object" ||
    typeof adapter.record !== "function" || typeof adapter.bindRoleAccess !== "function"
  ) fail();
  let resolveInvitation;
  let rejectInvitation;
  const invitationPromise = requireInvitation ? new Promise((resolvePromise, rejectPromise) => {
    resolveInvitation = resolvePromise;
    rejectInvitation = rejectPromise;
  }) : null;
  const result = new Promise((resolvePromise, rejectPromise) => {
    let stdout = "";
    let stderr = "";
    let lineBuffer = "";
    let observed = {};
    let settled = false;
    const claudeMcpToolCalls = new Map();
    function processLine(line) {
      if (line.trim().length === 0) return;
      let event;
      try { event = JSON.parse(line); } catch { fail(); }
      recordClaudeMcpToolCalls(event, claudeMcpToolCalls);
      bindCompletedRoleAccess(event, claudeMcpToolCalls, adapter, role);
      for (const value of completedMcpToolResults(event, claudeMcpToolCalls)) {
        for (const step of collectHelperSteps(value)) {
          if (
            step !== null && typeof step === "object" && !Array.isArray(step) &&
            ROLES.includes(step.role) && step.role !== role
          ) continue;
          adapter.record(step);
        }
      }
      observed = mergeObserved(observed, inspectEvent(event, role));
      if (observed.invitation !== undefined && resolveInvitation !== undefined) {
        resolveInvitation(observed.invitation);
        resolveInvitation = undefined;
        rejectInvitation = undefined;
      }
    }
    function processChunk(chunk) {
      stdout = append(stdout, chunk);
      lineBuffer += Buffer.from(chunk).toString("utf8");
      const lines = lineBuffer.split(/\r?\n/);
      lineBuffer = lines.pop() ?? "";
      lines.forEach(processLine);
    }
    function reject() {
      if (settled) return;
      settled = true;
      all.forEach(killProcessGroup);
      const error = new Error("Fresh agent compatibility check failed safely.");
      rejectInvitation?.(error);
      rejectPromise(error);
    }
    child.stdout?.on("data", (chunk) => { try { processChunk(chunk); } catch { reject(); } });
    child.stderr?.on("data", (chunk) => { try { stderr = append(stderr, chunk); } catch { reject(); } });
    child.once("error", reject);
    child.stdin?.once?.("error", reject);
    child.once("close", (code) => {
      child.__freshAgentClosed = true;
      if (settled) return;
      settled = true;
      if (code !== 0) {
        const error = new Error("Fresh agent compatibility check failed safely.");
        rejectInvitation?.(error);
        return rejectPromise(error);
      }
      try {
        if (lineBuffer.trim().length > 0) processLine(lineBuffer);
        assertSecretFree(stdout, canaries);
        assertSecretFree(stderr, canaries);
        if (observed.terminal === undefined || (requireInvitation && observed.invitation === undefined)) fail();
        resolvePromise(observed.terminal);
      } catch {
        const error = new Error("Fresh agent compatibility check failed safely.");
        rejectInvitation?.(error);
        rejectPromise(error);
      }
    });
  });
  return Object.freeze({ invitation: invitationPromise, result });
}

function sendPrompt(child, value) {
  if (typeof value !== "string" || value.length === 0 || typeof child.stdin?.end !== "function") fail();
  child.stdin.end(value);
}

export function responderPrompt(template, value) {
  if (typeof template !== "string") fail();
  const first = template.indexOf(RESPONDER_INVITATION_PLACEHOLDER);
  if (first < 0 || first !== template.lastIndexOf(RESPONDER_INVITATION_PLACEHOLDER)) fail();
  const keyFirst = template.indexOf(RESPONDER_ACCEPTANCE_KEY_PLACEHOLDER);
  if (keyFirst < 0 || keyFirst !== template.lastIndexOf(RESPONDER_ACCEPTANCE_KEY_PLACEHOLDER)) fail();
  const acceptanceKey = randomUUID();
  return template
    .replace(RESPONDER_INVITATION_PLACEHOLDER, invitation(value))
    .replace(RESPONDER_ACCEPTANCE_KEY_PLACEHOLDER, acceptanceKey);
}

function childEnvironment(room, credentials, { adapterBin } = {}) {
  if (credentials === null || typeof credentials !== "object" || Array.isArray(credentials)) fail();
  for (const [key, value] of Object.entries(credentials)) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(key) || typeof value !== "string" || value.length === 0) fail();
  }
  const path = adapterBin === undefined
    ? process.env.PATH ?? "/usr/bin:/bin"
    : `${descendant(room.workspace, adapterBin)}:${process.env.PATH ?? "/usr/bin:/bin"}`;
  return Object.freeze({
    ...credentials,
    CODEX_HOME: room.home,
    HOME: room.home,
    CLAUDE_CONFIG_DIR: join(room.home, ".claude"),
    GIT_CONFIG_NOSYSTEM: "1",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATH: path,
    TMPDIR: room.tmp,
    XDG_CACHE_HOME: room.cache,
  });
}

function publicRole(value) {
  return Object.freeze({
    address: value.address,
    certificateDigest: value.certificateDigest,
    certificateVerified: value.certificateVerified,
    erc8004: value.erc8004,
    externalBusinessActionPerformed: value.externalBusinessActionPerformed,
    policyDigest: value.policyDigest,
    receiptIds: value.receiptIds,
    role: value.role,
    sessionId: value.sessionId,
  });
}

export async function runFreshAgentHandshake({
  clients,
  configureClient,
  modelEnvironment = {},
  monitor,
  parent,
  prompts,
  release,
  spawnProcess = spawn,
  fetchReleaseAsset = defaultFetchReleaseAsset,
  releasePin,
  checkpointClientFactory = () => createStreamableMcpClient({ endpoint: CLOCKCHAIN_HANDSHAKE_MCP_URL }),
  contractClientFactory = () => createStreamableMcpClient({ endpoint: CLOCKCHAIN_HANDSHAKE_MCP_URL }),
  timeoutMs = 10 * 60 * 1000,
} = {}) {
  exactObject(clients, ROLES);
  exactObject(prompts, ROLES);
  exactObject(modelEnvironment, ROLES);
  if (typeof configureClient !== "function" || typeof monitor !== "function") fail();
  if (typeof fetchReleaseAsset !== "function") fail();
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60 * 60 * 1000) fail();
  const pin = validateReleaseAgreement(release);
  const canaries = ROLES.flatMap((role) => Object.values(modelEnvironment[role]));
  let run;
  const children = [];
  const adapters = [];
  const checkpointState = {};
  let checkpointClientPromise = null;
  const getCheckpointClient = async () => {
    if (checkpointClientPromise === null) {
      checkpointClientPromise = (async () => {
        const client = checkpointClientFactory();
        if (client === null || typeof client?.connect !== "function" || typeof client?.callTool !== "function") fail();
        await client.connect();
        return client;
      })();
    }
    return checkpointClientPromise;
  };
  let timer;
  try {
    // Preflight the endpoint contract before any workspace or model exists: the
    // private checkpoint flow is only coherent against the eight-tool surface.
    let contractTools;
    try {
      const contractClient = contractClientFactory();
      if (
        contractClient === null || typeof contractClient !== "object" ||
        typeof contractClient.connect !== "function" || typeof contractClient.listTools !== "function"
      ) fail();
      await contractClient.connect();
      contractTools = await contractClient.listTools();
    } catch {
      fail();
    }
    if (
      !Array.isArray(contractTools) ||
      contractTools.length !== CLOCKCHAIN_HANDSHAKE_TOOLS.length ||
      new Set(contractTools).size !== contractTools.length ||
      JSON.stringify([...contractTools].sort()) !== JSON.stringify([...CLOCKCHAIN_HANDSHAKE_TOOLS].sort())
    ) fail();
    const checkedInPin = releasePin === undefined ? await loadReleasePin() : releasePin;
    run = await createFreshAgentRun({ parent });
    const releaseAssets = await fetchVerifiedReleaseAssets(pin, checkedInPin, fetchReleaseAsset);
    const prepared = {};
    for (const role of ROLES) {
      const room = run.roles[role];
      await writeFile(join(room.workspace, "manifest.json"), releaseAssets.manifestBytes, { mode: 0o600 });
      await writeFile(join(room.workspace, "clockchain-agent-handshake.cjs"), releaseAssets.helperBytes, { mode: 0o600 });
      const adapterTmp = join(room.workspace, ".tmp");
      await privateDirectory(adapterTmp);
      const adapterRoom = Object.freeze({ ...room, tmp: adapterTmp });
      const socketRoot = await mkdtemp(join(tmpdir(), "clockchain-adapter-"));
      let recorder;
      try {
        recorder = await createVerifiedReleaseActionRecorder({
          manifestDigest: pin.manifestDigest,
          releaseAssets,
          room: adapterRoom,
          runtimeExecPath: process.execPath,
          socketRoot,
        });
      } catch (error) {
        await rm(socketRoot, { recursive: true, force: true }).catch(() => {});
        throw error;
      }
      // The completion handler must be installed before any retained action is
      // recorded so the first helper completion is never dropped. It builds,
      // signs, and submits the private proposal/acceptance checkpoints.
      const completionBinding = createCheckpointCompletionHandler({
        checkpointState,
        getCheckpointClient,
      });
      recorder.setCompletionHandler(completionBinding.handler);
      const adapter = Object.freeze({
        ...recorder,
        bindRoleAccess: completionBinding.bindRoleAccess,
        async close() {
          await recorder.close();
          await rm(socketRoot, { recursive: true, force: true });
        },
      });
      adapters.push(adapter);
      const client = cleanClient(clients[role]);
      const env = childEnvironment(adapterRoom, modelEnvironment[role], { adapterBin: recorder.bin });
      const configure = buildClientCommands({ client, manifestDigest: pin.manifestDigest, prompt: "configured later", workspace: room.workspace }).configure;
      await configureClient(Object.freeze({ client, command: configure, env, role, room: adapterRoom }));
      prepared[role] = { adapter, client, env };
    }
    const timedOut = new Promise((_, rejectPromise) => {
      timer = setTimeout(() => {
        children.forEach(killProcessGroup);
        rejectPromise(new Error("Fresh agent compatibility check failed safely."));
      }, timeoutMs);
    });
    const initiatorCommands = buildClientCommands({
      client: prepared.initiator.client,
      manifestDigest: pin.manifestDigest,
      prompt: prompts.initiator,
      workspace: run.roles.initiator.workspace,
    });
    const initiatorChild = spawnProcess(initiatorCommands.launch.file, initiatorCommands.launch.args, {
      cwd: run.roles.initiator.workspace,
      detached: true,
      env: prepared.initiator.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    children.push(initiatorChild);
    const initiatorObserved = observeChild(initiatorChild, "initiator", children, canaries, { adapter: prepared.initiator.adapter, requireInvitation: true });
    sendPrompt(initiatorChild, initiatorCommands.launch.input);
    const actualInvitation = await Promise.race([
      initiatorObserved.invitation,
      initiatorObserved.result.then(() => fail()),
      timedOut,
    ]);
    const responderCommands = buildClientCommands({
      client: prepared.responder.client,
      manifestDigest: pin.manifestDigest,
      prompt: responderPrompt(prompts.responder, actualInvitation),
      workspace: run.roles.responder.workspace,
    });
    const responderChild = spawnProcess(responderCommands.launch.file, responderCommands.launch.args, {
      cwd: run.roles.responder.workspace,
      detached: true,
      env: prepared.responder.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    children.push(responderChild);
    const responderObserved = observeChild(responderChild, "responder", children, canaries, { adapter: prepared.responder.adapter });
    sendPrompt(responderChild, responderCommands.launch.input);
    const results = await Promise.race([
      Promise.all([initiatorObserved.result, responderObserved.result]),
      timedOut,
    ]);
    clearTimeout(timer);
    timer = undefined;
    const [initiator, responder] = results;
    if (initiator.sessionId !== responder.sessionId || initiator.certificateDigest !== responder.certificateDigest) fail();
    if (initiator.address === responder.address || initiator.erc8004.agentId === responder.erc8004.agentId || initiator.policyDigest === responder.policyDigest) fail();
    const monitorResult = await monitor({ sessionId: initiator.sessionId });
    const chronology = monitorResult?.chronology;
    if (monitorResult?.sessionId !== initiator.sessionId || !Array.isArray(chronology) || chronology.at(-1) !== "CERTIFIED") fail();
    const evidence = Object.freeze({
      schema: EVIDENCE_SCHEMA,
      runId: run.runId,
      release: pin,
      clients: Object.freeze({ ...clients }),
      roles: Object.freeze({ initiator: publicRole(initiator), responder: publicRole(responder) }),
      monitor: Object.freeze({ chronology: Object.freeze([...chronology]), sessionId: monitorResult.sessionId }),
      cleanup: Object.freeze({ completed: true }),
    });
    assertSecretFree(evidence, [...canaries, actualInvitation, run.root]);
    await rm(run.root, { recursive: true, force: true });
    run = undefined;
    return evidence;
  } catch {
    fail();
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    children.forEach(killProcessGroup);
    for (const adapter of adapters) await adapter.close().catch(() => {});
    if (run !== undefined) await rm(run.root, { recursive: true, force: true }).catch(() => {});
  }
}
