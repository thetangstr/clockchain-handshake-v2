import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, mkdir, realpath, rm } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";

import { assertSecretFree } from "../core/redact.mjs";

export const CLOCKCHAIN_HANDSHAKE_MCP_URL = "https://mcp.clockchain.network/handshake/mcp";
export const FRESH_AGENT_CLIENTS = Object.freeze(["codex", "claude"]);

const ROLES = Object.freeze(["initiator", "responder"]);
const HELPER_OPERATIONS = Object.freeze([
  "init", "policy", "inspect", "register", "sign", "verify-certificate",
]);
const RELEASE_PREFIX = "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.0/";
const SAFE_SEGMENT = /^[A-Za-z0-9._-]+$/;
const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const TX = /^0x[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const UNSAFE_SHELL = /[\0\r\n;&|`$<>]/;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const TERMINAL_SCHEMA = "clockchain.fresh-agent-terminal-proof/v1";
const EVIDENCE_SCHEMA = "clockchain.fresh-agent-canary-evidence/v1";

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
  if (!SAFE_SEGMENT.test(asset) || asset === "." || asset === ".." || decodeURIComponent(asset) !== asset) fail();
  return raw;
}

function validateHelperArgv(argv, workspace) {
  if (!Array.isArray(argv) || argv.length < 4 || argv.some((entry) => typeof entry !== "string")) fail();
  argv.forEach(safeArg);
  descendant(workspace, argv[0]);
  if (!HELPER_OPERATIONS.includes(argv[1]) || argv[2] !== "--state-dir") fail();
  descendant(workspace, argv[3]);
  if (argv.length === 4) return;
  if (argv.length !== 6 || argv[4] !== "--payload-base64url" || !BASE64URL.test(argv[5])) fail();
}

export function validateHelperCommand({ argv, kind, workspace } = {}) {
  const cleanWorkspace = absolute(workspace);
  if (!Array.isArray(argv)) fail();
  if (kind === "download") {
    if (
      argv.length !== 8 || argv[0] !== "curl" || argv[1] !== "--fail" ||
      argv[2] !== "--location" || argv[3] !== "--proto" || argv[4] !== "=https" ||
      argv[5] !== "--output"
    ) fail();
    argv.forEach(safeArg);
    descendant(cleanWorkspace, argv[6]);
    validateAssetUrl(argv[7]);
    return true;
  }
  if (kind === "digest") {
    if (argv.length !== 4 || argv[0] !== "shasum" || argv[1] !== "-a" || argv[2] !== "256") fail();
    argv.forEach(safeArg);
    descendant(cleanWorkspace, argv[3]);
    return true;
  }
  if (kind === "helper") {
    validateHelperArgv(argv, cleanWorkspace);
    return true;
  }
  fail();
}

export function buildClientCommands({ client, prompt, workspace } = {}) {
  const clean = cleanClient(client);
  const cwd = absolute(workspace);
  if (typeof prompt !== "string" || prompt.length === 0) fail();
  if (clean === "codex") {
    return Object.freeze({
      configure: Object.freeze({
        args: Object.freeze(["mcp", "add", "clockchain-handshake", "--url", CLOCKCHAIN_HANDSHAKE_MCP_URL]),
        file: "codex",
      }),
      launch: Object.freeze({
        args: Object.freeze(["exec", "--skip-git-repo-check", "--sandbox", "workspace-write", "--cd", cwd, prompt]),
        file: "codex",
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
      args: Object.freeze(["-p", prompt, "--permission-mode", "acceptEdits"]),
      file: "claude",
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

function parseTerminal(value, role) {
  const lines = value.split(/\r?\n/).map((entry) => entry.trim()).filter(Boolean);
  if (lines.length === 0) fail();
  let parsed;
  try { parsed = JSON.parse(lines.at(-1)); } catch { fail(); }
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

function killProcessGroup(child) {
  if (!child || child.__freshAgentClosed === true) return;
  child.__freshAgentClosed = true;
  try {
    if (Number.isSafeInteger(child.pid) && child.pid > 0) process.kill(-child.pid, "SIGTERM");
    else child.kill?.("SIGTERM");
  } catch { child.kill?.("SIGTERM"); }
}

function waitForChild(child, role, all, canaries) {
  return new Promise((resolvePromise, rejectPromise) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    function reject() {
      if (settled) return;
      settled = true;
      all.forEach(killProcessGroup);
      rejectPromise(new Error("Fresh agent compatibility check failed safely."));
    }
    child.stdout?.on("data", (chunk) => { try { stdout = append(stdout, chunk); } catch { reject(); } });
    child.stderr?.on("data", (chunk) => { try { stderr = append(stderr, chunk); } catch { reject(); } });
    child.once("error", reject);
    child.once("close", (code) => {
      child.__freshAgentClosed = true;
      if (settled) return;
      settled = true;
      if (code !== 0) return rejectPromise(new Error("Fresh agent compatibility check failed safely."));
      try {
        assertSecretFree(stdout, canaries);
        assertSecretFree(stderr, canaries);
        resolvePromise(parseTerminal(stdout, role));
      } catch { rejectPromise(new Error("Fresh agent compatibility check failed safely.")); }
    });
  });
}

function childEnvironment(room, credentials) {
  if (credentials === null || typeof credentials !== "object" || Array.isArray(credentials)) fail();
  for (const [key, value] of Object.entries(credentials)) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(key) || typeof value !== "string" || value.length === 0) fail();
  }
  return Object.freeze({
    ...credentials,
    CODEX_HOME: room.home,
    HOME: room.home,
    CLAUDE_CONFIG_DIR: join(room.home, ".claude"),
    GIT_CONFIG_NOSYSTEM: "1",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATH: process.env.PATH ?? "/usr/bin:/bin",
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
  timeoutMs = 10 * 60 * 1000,
} = {}) {
  exactObject(clients, ROLES);
  exactObject(prompts, ROLES);
  exactObject(modelEnvironment, ROLES);
  if (typeof configureClient !== "function" || typeof monitor !== "function") fail();
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60 * 60 * 1000) fail();
  const pin = validateReleaseAgreement(release);
  const canaries = ROLES.flatMap((role) => Object.values(modelEnvironment[role]));
  let run;
  const children = [];
  let timer;
  try {
    run = await createFreshAgentRun({ parent });
    const prepared = {};
    for (const role of ROLES) {
      const client = cleanClient(clients[role]);
      const commands = buildClientCommands({ client, prompt: prompts[role], workspace: run.roles[role].workspace });
      const env = childEnvironment(run.roles[role], modelEnvironment[role]);
      await configureClient(Object.freeze({ client, command: commands.configure, env, role, room: run.roles[role] }));
      prepared[role] = { client, commands, env };
    }
    for (const role of ROLES) {
      const { commands, env } = prepared[role];
      children.push(spawnProcess(commands.launch.file, commands.launch.args, {
        cwd: run.roles[role].workspace,
        detached: true,
        env,
        stdio: ["ignore", "pipe", "pipe"],
      }));
    }
    const timedOut = new Promise((_, rejectPromise) => {
      timer = setTimeout(() => {
        children.forEach(killProcessGroup);
        rejectPromise(new Error("Fresh agent compatibility check failed safely."));
      }, timeoutMs);
    });
    const results = await Promise.race([
      Promise.all(ROLES.map((role, index) => waitForChild(children[index], role, children, canaries))),
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
    assertSecretFree(evidence, [...canaries, run.root]);
    await rm(run.root, { recursive: true, force: true });
    run = undefined;
    return evidence;
  } catch {
    fail();
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    children.forEach(killProcessGroup);
    if (run !== undefined) await rm(run.root, { recursive: true, force: true }).catch(() => {});
  }
}
