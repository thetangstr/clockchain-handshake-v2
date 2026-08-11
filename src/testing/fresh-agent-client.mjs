import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, mkdir, realpath, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, isAbsolute, join, relative, resolve } from "node:path";

import { assertSecretFree } from "../core/redact.mjs";
import { agentHandshakeV2StatementDigest } from "../agent-handshake/v2/terms.mjs";
import {
  AGENT_HANDSHAKE_V2_SNAPSHOT_SCHEMA,
  buildAgentHandshakeV2Snapshot,
} from "../monitor/agent-snapshot-v2.mjs";

const ROLES = Object.freeze(["initiator", "responder"]);
const HELPER_OPERATIONS = Object.freeze([
  "init", "policy", "inspect", "register", "sign", "verify-certificate",
]);
const RELEASE_PREFIX = "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.2/";

export const CLOCKCHAIN_HANDSHAKE_MCP_URL = "https://mcp.clockchain.network/handshake/mcp";
export const FRESH_AGENT_CLIENTS = Object.freeze(["codex", "claude"]);
export const CLOCKCHAIN_HANDSHAKE_TOOLS = Object.freeze([
  "agent_handshake_invite",
  "agent_handshake_accept_invitation",
  "agent_handshake_join",
  "agent_handshake_status",
  "agent_handshake_next",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);
export const VERIFIED_HELPER_BOOTSTRAP = 'const fs=require("node:fs");const crypto=require("node:crypto");const Module=require("node:module");const argv=process.argv.slice(1);const expected=argv.shift();const manifestPath=argv.shift();const helperPath=argv.shift();const manifestBytes=fs.readFileSync(manifestPath);const manifestDigest=crypto.createHash("sha256").update(manifestBytes).digest("hex");if(manifestDigest!==expected)process.exit(86);const manifest=JSON.parse(manifestBytes);if(manifest.schema!=="clockchain.agent-handshake-release-manifest/v1"||manifest.version!=="2.1.2"||!Array.isArray(manifest.assets)||manifest.assets.length!==1)process.exit(86);const asset=manifest.assets[0];if(asset.filename!=="clockchain-agent-handshake.cjs"||asset.url!=="https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.2/clockchain-agent-handshake.cjs"||typeof asset.sha256!=="string"||!/^[0-9a-f]{64}$/.test(asset.sha256))process.exit(86);const helperBytes=fs.readFileSync(helperPath);const helperDigest=crypto.createHash("sha256").update(helperBytes).digest("hex");if(helperDigest!==asset.sha256)process.exit(86);process.argv=[process.execPath].concat(helperPath).concat(argv);const loaded=new Module(helperPath);loaded.filename=helperPath;loaded.paths=[];const compile=loaded._compile.bind(loaded);compile(...[helperBytes.toString("utf8")].concat(helperPath));';

const SAFE_SEGMENT = /^[A-Za-z0-9._-]+$/;
const SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const TX = /^0x[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const ROLE_TOKEN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const ROLE_ACCESS_KEYS = Object.freeze([
  "v", "alg", "typ", "iss", "aud", "kid", "jti", "sessionId", "role",
  "statementDigest", "allowedTools", "nbfMs", "expMs",
]);
const UNSAFE_SHELL = /[\0\r\n;&|`$<>]/;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const HELPER_RESULT_SCHEMA = "clockchain.agent-handshake-cli-result/v1";
const EVIDENCE_SCHEMA = "clockchain.fresh-agent-canary-evidence/v1";
const RESPONDER_INVITATION_PLACEHOLDER = "<PASTE THE INITIATOR INVITATION>";
export const CLAUDE_CONTEXT_MARKER = "CLOCKCHAIN_CONTEXT_RECEIVED";
export const CLAUDE_CONTEXT_PROMPT = `I am using this fresh disposable workspace for an expected Clockchain test. In my next message I will provide a concrete role-specific request. Do not perform any action now; evaluate that later request on its own exact scope and safety boundaries. Reply exactly ${CLAUDE_CONTEXT_MARKER}.`;
const TRACE_LIFECYCLE = process.env.CLOCKCHAIN_FRESH_AGENT_TRACE === "1";

function traceLifecycle(value) {
  if (TRACE_LIFECYCLE) process.stderr.write(`${JSON.stringify(value)}\n`);
}

function traceText(value, canaries) {
  if (!TRACE_LIFECYCLE || typeof value !== "string") return null;
  let redacted = value
    .replace(/[A-Za-z0-9_-]{80,}\.[A-Za-z0-9_-]{40,}/gu, "[ROLE_ACCESS]")
    .replace(/0x[0-9a-fA-F]{64}/gu, "[HEX_32]");
  for (const canary of canaries) redacted = redacted.replaceAll(canary, "[SECRET]");
  return redacted.slice(0, 2_000);
}

function traceAccessClaims(value) {
  if (!TRACE_LIFECYCLE || typeof value !== "string") return null;
  try {
    const parsed = JSON.parse(Buffer.from(value.split(".")[0], "base64url").toString("utf8"));
    return {
      allowedTools: Array.isArray(parsed.allowedTools) ? parsed.allowedTools : null,
      role: typeof parsed.role === "string" ? parsed.role : null,
      sessionId: typeof parsed.sessionId === "string" ? parsed.sessionId : null,
    };
  } catch {
    return null;
  }
}

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

const MANIFEST_DOWNLOAD_COMMAND =
  `curl --fail --location --proto '=https' --proto-redir '=https' --output ./manifest.json '${RELEASE_PREFIX}manifest.json'`;
const HELPER_DOWNLOAD_COMMAND =
  `curl --fail --location --proto '=https' --proto-redir '=https' --output ./clockchain-agent-handshake.cjs '${RELEASE_PREFIX}clockchain-agent-handshake.cjs'`;

export function classifyClaudeBashCommand(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024 * 1024) fail();
  const trimmed = value.trim();
  const kind = ["curl", "mkdir", "node"].find((name) => new RegExp(`(^|\\n)\\s*${name} `).test(trimmed)) ?? "other";
  const operators = trimmed.match(/&&|\|\||;|\n/g) ?? [];
  return Object.freeze({
    compound: operators.length > 0,
    contains: Object.freeze({
      curl: /(^|[^a-z])curl(?:\s|$)/i.test(trimmed),
      helperUrl: trimmed.includes(`${RELEASE_PREFIX}clockchain-agent-handshake.cjs`),
      manifestUrl: trimmed.includes(`${RELEASE_PREFIX}manifest.json`),
      mkdir: /(^|[^a-z])mkdir(?:\s|$)/i.test(trimmed),
      node: /(^|[^a-z])node(?:\s|$)/i.test(trimmed),
      sha256Command: /(^|[^a-z])(sha256sum|shasum)(?:\s|$)/i.test(trimmed),
      shellWrapper: /(^|[;&|\n])\s*(set|sh|bash)(?:\s|$)/i.test(trimmed),
    }),
    exactDownload: trimmed === MANIFEST_DOWNLOAD_COMMAND
      ? "manifest"
      : trimmed === HELPER_DOWNLOAD_COMMAND ? "helper" : null,
    hasLineContinuation: /\\\r?\n/.test(trimmed),
    kind,
    operatorCount: operators.length,
    prefixed: kind !== "other" && !trimmed.startsWith(`${kind} `),
  });
}

export function classifyHelperExecutionCommand(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024 * 1024) fail();
  const operation = HELPER_OPERATIONS.find((name) =>
    new RegExp(`clockchain-agent-handshake\\.cjs(?:["']|\\s)+${name}(?:\\s|$)`).test(value),
  ) ?? null;
  let statePathClass = null;
  if (/\$TMPDIR\/\.clockchain\/handshakes\//.test(value)) statePathClass = "tmpdir-session";
  else if (/\$PWD\/\.clockchain\/handshakes\//.test(value)) statePathClass = "pwd-session";
  else if (/\/(?:[^\s"']+\/)*\.clockchain\/handshakes\//.test(value)) statePathClass = "absolute-session";
  return Object.freeze({
    helperBootstrap: value.includes("clockchain-agent-handshake.cjs") && value.includes("--input-type=commonjs"),
    operation,
    payloadFlag: value.includes("--payload-base64url"),
    statePathClass,
  });
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
      argv.length !== 10 || argv[0] !== "curl" || argv[1] !== "--fail" ||
      argv[2] !== "--location" || argv[3] !== "--proto" || argv[4] !== "=https" ||
      argv[5] !== "--proto-redir" || argv[6] !== "=https" || argv[7] !== "--output"
    ) fail();
    argv.forEach(safeArg);
    const output = descendant(cleanWorkspace, argv[8]);
    const download = validateAssetUrl(argv[9]);
    if (basename(output) !== download.asset) fail();
    return true;
  }
  if (kind === "helper") {
    validateHelperArgv(argv, cleanWorkspace, manifestDigest);
    return true;
  }
  fail();
}

export function buildClaudeSandboxSettings({ hostHome = homedir(), hostUid = process.getuid?.(), workspace } = {}) {
  const cleanHome = absolute(hostHome);
  const cwd = absolute(workspace);
  if (!Number.isSafeInteger(hostUid) || hostUid < 0) fail();
  const deniedRead = Object.freeze([...new Set([cleanHome, "/Volumes", "/private/tmp"])]);
  const deniedWrite = Object.freeze([...new Set([cleanHome, "/Volumes"])]);
  return Object.freeze({
    permissions: Object.freeze({
      deny: Object.freeze(["Edit", "NotebookEdit", "WebFetch", "WebSearch", "Write"]),
    }),
    sandbox: Object.freeze({
      allowUnsandboxedCommands: false,
      autoAllowBashIfSandboxed: true,
      enabled: true,
      failIfUnavailable: true,
      filesystem: Object.freeze({
        allowRead: Object.freeze([cwd]),
        denyRead: deniedRead,
        denyWrite: deniedWrite,
      }),
      network: Object.freeze({
        allowedDomains: Object.freeze([
          "github.com",
          "release-assets.githubusercontent.com",
          "11155111.rpc.thirdweb.com",
          "ethereum-sepolia-rpc.publicnode.com",
        ]),
      }),
    }),
  });
}

export function buildClientCommands({ client, claudeSessionId, hostHome = homedir(), hostUid = process.getuid?.(), manifestDigest, prompt, workspace } = {}) {
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
          "exec", "--model", "gpt-5.6-terra", "--skip-git-repo-check", "--strict-config", "--ignore-rules", "--ephemeral",
          "--sandbox", "workspace-write", "--config", 'approval_policy="never"',
          "--config", "sandbox_workspace_write.network_access=true", "--json", "--cd", cwd, "-",
        ]),
        file: "codex",
        input: prompt,
        limitation: "Codex workspace-write does not provide literal command-pattern enforcement.",
      }),
    });
  }
  if (!UUID.test(claudeSessionId)) fail();
  const sandboxSettings = buildClaudeSandboxSettings({ hostHome, hostUid, workspace: cwd });
  return Object.freeze({
    configure: Object.freeze({
      args: Object.freeze(["mcp", "add", "--transport", "http", "--scope", "user", "clockchain-handshake", CLOCKCHAIN_HANDSHAKE_MCP_URL]),
      file: "claude",
    }),
    prepare: Object.freeze({
      args: Object.freeze([
        "--print", "--model", "sonnet", "--effort", "low", "--session-id", claudeSessionId,
        "--disable-slash-commands", "--no-chrome", "--permission-mode", "dontAsk",
        "--setting-sources", "", "--output-format", "json",
      ]),
      file: "claude",
      input: CLAUDE_CONTEXT_PROMPT,
    }),
    launch: Object.freeze({
      args: Object.freeze([
        "--print", "--resume", claudeSessionId, "--model", "sonnet", "--effort", "low", "--disable-slash-commands", "--no-chrome",
        "--strict-mcp-config", "--mcp-config", JSON.stringify({
          mcpServers: { "clockchain-handshake": { type: "http", url: CLOCKCHAIN_HANDSHAKE_MCP_URL } },
        }),
        "--permission-mode", "dontAsk",
        "--setting-sources", "",
        "--settings", JSON.stringify(sandboxSettings),
        "--output-format", "stream-json",
        "--verbose",
        "--allowedTools", ["ToolSearch", "Bash"].concat(CLOCKCHAIN_HANDSHAKE_TOOLS
          .map((tool) => `mcp__clockchain-handshake__${tool}`)
          .concat(["Read(./manifest.json)", "Read(./clockchain-agent-handshake.cjs)"]))
          .join(","),
      ]),
      file: "claude",
      input: prompt,
      limitation: null,
    }),
  });
}

export function validateClaudePreparation(output, canaries = []) {
  if (typeof output !== "string" || !Array.isArray(canaries)) fail();
  assertSecretFree(output, canaries);
  let parsed;
  try { parsed = JSON.parse(output); } catch {
    traceLifecycle({ phase: "prepare-result", client: "claude", parseable: false });
    fail();
  }
  traceLifecycle({
    phase: "prepare-result",
    client: "claude",
    parseable: true,
    subtype: typeof parsed?.subtype === "string" ? parsed.subtype : null,
    isError: parsed?.is_error === true,
    markerMatches: typeof parsed?.result === "string" && parsed.result.trim() === CLAUDE_CONTEXT_MARKER,
  });
  if (
    parsed === null || typeof parsed !== "object" || Array.isArray(parsed) ||
    parsed.subtype !== "success" || parsed.is_error !== false ||
    typeof parsed.result !== "string" || parsed.result.trim() !== CLAUDE_CONTEXT_MARKER
  ) fail();
  return true;
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
    for (const name of ["home", "workspace", "cache", "state"]) {
      entry[name] = join(roleRoot, name);
      await privateDirectory(entry[name]);
    }
    entry.tmp = join(entry.workspace, ".tmp");
    await privateDirectory(entry.tmp);
    roles[role] = Object.freeze(entry);
  }
  return Object.freeze({ root, roles: Object.freeze(roles), runId });
}

function append(output, chunk) {
  const next = output + Buffer.from(chunk).toString("utf8");
  if (Buffer.byteLength(next) > MAX_OUTPUT_BYTES) fail();
  return next;
}

function validateRegistration(parsed) {
  const identity = exactObject(parsed, [
    "agentId", "chainId", "reference", "registrationBlock", "registrationTx", "registryAddress",
  ]);
  if (
    !DECIMAL.test(identity.agentId) || identity.chainId !== "eip155:11155111" ||
    !ADDRESS.test(identity.registryAddress) ||
    identity.reference !== `${identity.chainId}:${identity.registryAddress}:${identity.agentId}` ||
    !TX.test(identity.registrationTx) || !DECIMAL.test(identity.registrationBlock)
  ) fail();
  return Object.freeze({ ...identity });
}

function validateHelperProof(parsed, role) {
  exactObject(parsed, [
    "certificateVerified", "externalBusinessActionPerformed", "helperVersion", "identity", "operation",
    "outcome", "policyDigest", "role", "schema", "sessionId", "statementDigest",
  ]);
  if (
    parsed.schema !== HELPER_RESULT_SCHEMA || parsed.helperVersion !== "2.1.2" ||
    parsed.operation !== "verify-certificate" || parsed.outcome !== "VERIFIED" ||
    parsed.role !== role || !UUID.test(parsed.sessionId) || !SHA256.test(parsed.policyDigest) ||
    !SHA256.test(parsed.statementDigest) || parsed.certificateVerified !== true ||
    parsed.externalBusinessActionPerformed !== false
  ) fail();
  const identity = exactObject(parsed.identity, ["erc8004", "policyDigest", "sessionKeyAddress"]);
  if (!ADDRESS.test(identity.sessionKeyAddress) || identity.policyDigest !== parsed.policyDigest) fail();
  return Object.freeze({
    ...parsed,
    identity: Object.freeze({
      sessionKeyAddress: identity.sessionKeyAddress,
      policyDigest: identity.policyDigest,
      erc8004: validateRegistration(identity.erc8004),
    }),
  });
}

function invitation(value) {
  if (typeof value !== "string" || value.length < 80 || value.length > 4096 || !ROLE_TOKEN.test(value)) fail();
  const [payloadSegment, signatureSegment] = value.split(".");
  const payloadBytes = Buffer.from(payloadSegment, "base64url");
  const signatureBytes = Buffer.from(signatureSegment, "base64url");
  if (
    payloadBytes.toString("base64url") !== payloadSegment ||
    signatureBytes.length !== 32 || signatureBytes.toString("base64url") !== signatureSegment
  ) fail();
  let parsed;
  try { parsed = JSON.parse(payloadBytes.toString("utf8")); } catch { fail(); }
  const access = exactObject(parsed, ROLE_ACCESS_KEYS);
  const canonical = Object.fromEntries(Object.entries(access).sort(([left], [right]) => left.localeCompare(right)));
  if (
    JSON.stringify(canonical) !== payloadBytes.toString("utf8") ||
    access.v !== 1 || access.alg !== "HS256" ||
    access.typ !== "clockchain-agent-handshake-role-access" ||
    access.iss !== "https://mcp.clockchain.network" || access.aud !== "clockchain-agent-handshake" ||
    typeof access.kid !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(access.kid) ||
    !UUID.test(access.jti) || !UUID.test(access.sessionId) || access.role !== "responder" ||
    !SHA256.test(access.statementDigest) ||
    JSON.stringify(access.allowedTools) !== JSON.stringify(["agent_handshake_accept_invitation"]) ||
    typeof access.nbfMs !== "string" || !DECIMAL.test(access.nbfMs) ||
    typeof access.expMs !== "string" || !DECIMAL.test(access.expMs) ||
    BigInt(access.nbfMs) >= BigInt(access.expMs)
  ) fail();
  return value;
}

function invitationMessage(value) {
  if (typeof value !== "string") return null;
  const clean = value.trim();
  return ROLE_TOKEN.test(clean) ? invitation(clean) : null;
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
  if (["agent_message", "text"].includes(value.type) && Object.hasOwn(value, "text")) {
    const candidate = invitationMessage(value.text);
    if (candidate !== null) found = { invitation: candidate };
  }
  if (Object.hasOwn(value, "responderInvitation")) {
    found = { invitation: invitation(value.responderInvitation) };
  }
  for (const entry of Object.values(value)) {
    found = mergeObserved(found, inspectEvent(entry, role, depth + 1));
  }
  return found;
}

function mergeObserved(left, right) {
  const merged = { ...left };
  for (const key of ["invitation", "helperProof"]) {
    if (right[key] === undefined) continue;
    if (merged[key] !== undefined && JSON.stringify(merged[key]) !== JSON.stringify(right[key])) fail();
    merged[key] = right[key];
  }
  return merged;
}

function parsedHelperProof(value, role) {
  if (typeof value !== "string") return null;
  const parsed = parseJsonString(value);
  if (parsed === null || parsed?.schema !== HELPER_RESULT_SCHEMA) return null;
  return validateHelperProof(parsed, role);
}

function validateVerifyCertificateCommand(value, proof, manifestDigest) {
  if (typeof value !== "string" || value !== value.trim() || !SHA256.test(manifestDigest)) fail();
  const stateDir = `$TMPDIR/.clockchain/handshakes/${proof.sessionId}/${proof.role}`;
  const prefix = `node --input-type=commonjs --eval '${VERIFIED_HELPER_BOOTSTRAP}' ${manifestDigest} ./manifest.json ./clockchain-agent-handshake.cjs verify-certificate --state-dir "${stateDir}" --payload-base64url `;
  if (!value.startsWith(prefix)) fail();
  const encoded = value.slice(prefix.length);
  if (!BASE64URL.test(encoded)) fail();
  const bytes = Buffer.from(encoded, "base64url");
  if (bytes.toString("base64url") !== encoded) fail();
  let parsed;
  try { parsed = JSON.parse(bytes.toString("utf8")); } catch { fail(); }
  const payload = exactObject(parsed, [
    "schema", "helperVersion", "role", "sessionId", "repositorySha", "sessionDeadlineMs",
    "certificate", "externalBusinessActionPerformed",
  ]);
  if (
    payload.schema !== "clockchain.agent-handshake-certificate-verification/v1" ||
    payload.helperVersion !== "2.1.2" || payload.role !== proof.role ||
    payload.sessionId !== proof.sessionId || !SHA.test(payload.repositorySha) ||
    !DECIMAL.test(payload.sessionDeadlineMs) || payload.certificate === null ||
    typeof payload.certificate !== "object" || Array.isArray(payload.certificate) ||
    payload.externalBusinessActionPerformed !== false
  ) fail();
}

function helperProofFromEvent(event, role, manifestDigest, claudeBashCommands) {
  if (
    event?.type === "item.completed" && event?.item?.type === "command_execution" &&
    event.item.status === "completed" && event.item.exit_code === 0
  ) {
    const proof = parsedHelperProof(event.item.aggregated_output, role);
    if (proof === null) return null;
    validateVerifyCertificateCommand(event.item.command, proof, manifestDigest);
    return proof;
  }
  if (event?.type === "assistant" && Array.isArray(event?.message?.content)) {
    for (const block of event.message.content) {
      if (block?.type !== "tool_use" || block?.name !== "Bash") continue;
      if (typeof block.id !== "string" || block.id.length === 0 || typeof block?.input?.command !== "string") fail();
      if (claudeBashCommands.has(block.id)) fail();
      claudeBashCommands.set(block.id, block.input.command);
    }
    return null;
  }
  if (event?.type !== "user" || !Array.isArray(event?.message?.content)) return null;
  let found = null;
  for (const block of event.message.content) {
    if (block?.type !== "tool_result" || block.is_error === true) continue;
    const parsed = parsedHelperProof(block.content, role);
    if (parsed === null) continue;
    if (typeof block.tool_use_id !== "string") fail();
    const command = claudeBashCommands.get(block.tool_use_id);
    if (typeof command !== "string") fail();
    validateVerifyCertificateCommand(command, parsed, manifestDigest);
    claudeBashCommands.set(block.tool_use_id, null);
    if (found !== null && JSON.stringify(found) !== JSON.stringify(parsed)) fail();
    found = parsed;
  }
  return found;
}

function killProcessGroup(child) {
  if (!child || child.__freshAgentClosed === true) return;
  child.__freshAgentClosed = true;
  try {
    if (Number.isSafeInteger(child.pid) && child.pid > 0) process.kill(-child.pid, "SIGTERM");
    else child.kill?.("SIGTERM");
  } catch { child.kill?.("SIGTERM"); }
}

function observeChild(child, role, all, canaries, { expectedInvitation, manifestDigest, requireInvitation = false } = {}) {
  if (!SHA256.test(manifestDigest)) fail();
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
    const claudeBashCommands = new Map();
    let settled = false;
    function processLine(line) {
      if (line.trim().length === 0) return;
      let event;
      try { event = JSON.parse(line); } catch { fail(); }
      observed = mergeObserved(observed, inspectEvent(event, role));
      const helperProof = helperProofFromEvent(event, role, manifestDigest, claudeBashCommands);
      if (helperProof !== null) observed = mergeObserved(observed, { helperProof });
      traceLifecycle({
        phase: "event",
        role,
        type: ["thread.started", "turn.started", "item.started", "item.completed", "turn.completed", "system", "assistant", "user", "result", "rate_limit_event"].includes(event?.type) ? event.type : "other",
        subtype: typeof event?.subtype === "string" && /^[a-z_.-]+$/.test(event.subtype) ? event.subtype : null,
        invitationObserved: observed.invitation !== undefined,
        terminalObserved: observed.helperProof !== undefined,
        mcpConnected: event?.type === "system" && Array.isArray(event.mcp_servers)
          ? event.mcp_servers.some((entry) => entry?.name === "clockchain-handshake" && entry?.status === "connected")
          : false,
        blocks: event?.type === "assistant" && Array.isArray(event?.message?.content)
          ? event.message.content.map((block) => ({
              type: ["thinking", "text", "tool_use", "tool_result"].includes(block?.type) ? block.type : "other",
              tool: typeof block?.name === "string" && (
                CLOCKCHAIN_HANDSHAKE_TOOLS.some((name) => block.name.endsWith(`__${name}`)) ||
                block.name === "Bash"
              ) ? block.name : null,
              bashShape: block?.name === "Bash" && typeof block?.input?.command === "string"
                ? classifyClaudeBashCommand(block.input.command)
                : null,
              helperShape: block?.name === "Bash" && typeof block?.input?.command === "string"
                ? classifyHelperExecutionCommand(block.input.command)
                : null,
            }))
          : [],
        userBlocks: event?.type === "user" && Array.isArray(event?.message?.content)
          ? event.message.content.map((block) => ({
              type: ["text", "tool_result"].includes(block?.type) ? block.type : "other",
              isError: block?.is_error === true,
            }))
          : [],
        texts: event?.type === "assistant" && Array.isArray(event?.message?.content)
          ? event.message.content
            .filter((block) => block?.type === "text")
            .map((block) => traceText(block.text, canaries))
          : [],
        userTexts: event?.type === "user" && Array.isArray(event?.message?.content)
          ? event.message.content
            .filter((block) => block?.type === "text")
            .map((block) => traceText(block.text, canaries))
          : [],
        resultErrors: event?.type === "result"
          ? [event.error, ...(Array.isArray(event.errors) ? event.errors : [])]
            .filter((entry) => typeof entry === "string")
            .map((entry) => traceText(entry, canaries))
          : [],
        codexItem: ["item.started", "item.completed"].includes(event?.type) && event?.item
          ? {
              type: ["reasoning", "agent_message", "mcp_tool_call", "command_execution"].includes(event.item.type)
                ? event.item.type
                : "other",
              tool: typeof event.item.tool === "string" && CLOCKCHAIN_HANDSHAKE_TOOLS.includes(event.item.tool)
                ? event.item.tool
                : null,
              status: ["in_progress", "completed", "failed"].includes(event.item.status) ? event.item.status : null,
              exitCode: Number.isSafeInteger(event.item.exit_code) ? event.item.exit_code : null,
              helperShape: event.item.type === "command_execution" && typeof event.item.command === "string"
                ? classifyHelperExecutionCommand(event.item.command)
                : null,
              text: event.item.type === "agent_message" ? traceText(event.item.text, canaries) : null,
              accessPresent: event.item.type === "mcp_tool_call" && [
                "agent_handshake_join",
                "agent_handshake_status",
                "agent_handshake_next",
                "agent_handshake_submit",
                "agent_handshake_get_certificate",
              ].includes(event.item.tool)
                ? typeof event.item.arguments?.access === "string" && event.item.arguments.access.length > 0
                : null,
              accessClaims: event.item.type === "mcp_tool_call"
                ? traceAccessClaims(event.item.arguments?.access)
                : null,
              joinInput: event.item.type === "mcp_tool_call" && event.item.tool === "agent_handshake_join"
                ? {
                    accessPresent: typeof event.item.arguments?.access === "string" && event.item.arguments.access.length > 0,
                    helperVersion: typeof event.item.arguments?.helperVersion === "string" ? event.item.arguments.helperVersion : null,
                    policyDigest: typeof event.item.arguments?.policyDigest === "string" ? event.item.arguments.policyDigest : null,
                    sessionKeyAddress: typeof event.item.arguments?.sessionKeyAddress === "string" ? event.item.arguments.sessionKeyAddress : null,
                  }
                : null,
              invitationInput: event.item.type === "mcp_tool_call" && event.item.tool === "agent_handshake_accept_invitation"
                ? {
                    present: typeof event.item.arguments?.invitation === "string",
                    matchesExpected: typeof expectedInvitation === "string" && event.item.arguments?.invitation === expectedInvitation,
                    claims: traceAccessClaims(event.item.arguments?.invitation),
                  }
                : null,
            }
          : null,
        isError: event?.type === "result" ? event.is_error === true : false,
        permissionDenials: event?.type === "result" && Array.isArray(event.permission_denials)
          ? event.permission_denials.length
          : 0,
      });
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
      traceLifecycle({ phase: "close", role, code: Number.isSafeInteger(code) ? code : null, stderrBytes: Buffer.byteLength(stderr) });
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
        if (observed.helperProof === undefined || (requireInvitation && observed.invitation === undefined)) fail();
        resolvePromise(observed.helperProof);
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

function responderPrompt(template, value) {
  if (typeof template !== "string") fail();
  const first = template.indexOf(RESPONDER_INVITATION_PLACEHOLDER);
  if (first < 0 || first !== template.lastIndexOf(RESPONDER_INVITATION_PLACEHOLDER)) fail();
  return template.replace(RESPONDER_INVITATION_PLACEHOLDER, invitation(value));
}

function childEnvironment(room, credentials) {
  if (credentials === null || typeof credentials !== "object" || Array.isArray(credentials)) fail();
  for (const [key, value] of Object.entries(credentials)) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(key) || typeof value !== "string" || value.length === 0) fail();
  }
  return Object.freeze({
    ...credentials,
    CODEX_HOME: room.home,
    CLAUDE_CODE_TMPDIR: room.tmp,
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

function validateMonitorRole(value) {
  const item = exactObject(value, ["address", "erc8004", "policyDigest"]);
  if (!ADDRESS.test(item.address) || !SHA256.test(item.policyDigest)) fail();
  return Object.freeze({ address: item.address, policyDigest: item.policyDigest, erc8004: validateRegistration(item.erc8004) });
}

function validateMonitorResult(value, expectedSessionId) {
  const item = exactObject(value, [
    "certificateDigest", "chronology", "externalBusinessActionPerformed", "receiptIds", "roles", "sessionId", "statementDigest",
  ]);
  if (
    item.sessionId !== expectedSessionId || !UUID.test(item.sessionId) || !SHA256.test(item.certificateDigest) ||
    !SHA256.test(item.statementDigest) || item.externalBusinessActionPerformed !== false ||
    !Array.isArray(item.chronology) || item.chronology.at(-1) !== "CERTIFIED" ||
    item.chronology.some((entry) => typeof entry !== "string" || entry.length === 0) ||
    !Array.isArray(item.receiptIds) || item.receiptIds.length !== 3 || new Set(item.receiptIds).size !== 3 ||
    item.receiptIds.some((entry) => typeof entry !== "string" || entry.length === 0)
  ) fail();
  const roles = exactObject(item.roles, ROLES);
  return Object.freeze({
    ...item,
    chronology: Object.freeze([...item.chronology]),
    receiptIds: Object.freeze([...item.receiptIds]),
    roles: Object.freeze({ initiator: validateMonitorRole(roles.initiator), responder: validateMonitorRole(roles.responder) }),
  });
}

export function validateFreshAgentMonitorSnapshot(value, expectedSessionId) {
  if (!UUID.test(expectedSessionId) || value?.schema !== AGENT_HANDSHAKE_V2_SNAPSHOT_SCHEMA) return null;
  let snapshot;
  try { snapshot = buildAgentHandshakeV2Snapshot(value); } catch { fail(); }
  if (snapshot.sessionId !== expectedSessionId) return null;
  if (snapshot.failure !== null || snapshot.checker.stage === "FAILED") fail();
  const complete = snapshot.invitation.responderClaimedAtMs !== null &&
    ROLES.every((role) => snapshot.policies[role] !== null && snapshot.parties[role] !== null && snapshot.evidence[role] !== null) &&
    snapshot.statements.proposalDigest !== null && snapshot.statements.acceptanceDigest !== null &&
    ["proposal", "acceptance", "acknowledgment"].every((kind) => snapshot.receipts[kind] !== null) &&
    snapshot.checker.stage === "VERIFIED" && snapshot.certificate?.outcome === "VERIFIED";
  if (!complete) return null;
  const terms = { ...snapshot.terms, validForSeconds: snapshot.timing.agreementValidForSeconds };
  return validateMonitorResult({
    certificateDigest: snapshot.certificate.digest,
    chronology: [
      "SESSION_STARTED", "INVITATION_CLAIMED", "POLICIES_COMMITTED", "IDENTITIES_REGISTERED",
      "STATEMENT_PROPOSED", "STATEMENT_ACCEPTED", "PROPOSED", "ACCEPTED", "ACKNOWLEDGED",
      "EVIDENCE_RECEIVED", "VERIFIED", "CERTIFIED",
    ],
    externalBusinessActionPerformed: snapshot.externalBusinessActionPerformed,
    receiptIds: [snapshot.receipts.proposal.ledgerId, snapshot.receipts.acceptance.ledgerId, snapshot.receipts.acknowledgment.ledgerId],
    roles: Object.fromEntries(ROLES.map((role) => [role, {
      address: snapshot.parties[role].sessionKeyAddress,
      erc8004: snapshot.parties[role].erc8004,
      policyDigest: snapshot.policies[role].digest,
    }])),
    sessionId: snapshot.sessionId,
    statementDigest: agentHandshakeV2StatementDigest(terms),
  }, expectedSessionId);
}

function publicRole(value, monitorResult) {
  const role = monitorResult.roles[value.role];
  if (
    value.sessionId !== monitorResult.sessionId || value.statementDigest !== monitorResult.statementDigest ||
    value.policyDigest !== role.policyDigest || value.identity.sessionKeyAddress !== role.address ||
    JSON.stringify(value.identity.erc8004) !== JSON.stringify(role.erc8004)
  ) fail();
  return Object.freeze({
    address: role.address,
    certificateDigest: monitorResult.certificateDigest,
    certificateVerified: value.certificateVerified,
    erc8004: role.erc8004,
    externalBusinessActionPerformed: value.externalBusinessActionPerformed,
    policyDigest: value.policyDigest,
    receiptIds: monitorResult.receiptIds,
    role: value.role,
    sessionId: value.sessionId,
  });
}

export async function runFreshAgentHandshake({
  clients,
  configureClient,
  modelEnvironment = {},
  secretCanaries = { initiator: [], responder: [] },
  monitor,
  parent,
  prepareClient,
  prompts,
  release,
  spawnProcess = spawn,
  timeoutMs = 10 * 60 * 1000,
} = {}) {
  exactObject(clients, ROLES);
  exactObject(prompts, ROLES);
  exactObject(modelEnvironment, ROLES);
  exactObject(secretCanaries, ROLES);
  if (typeof configureClient !== "function" || typeof monitor !== "function" || typeof prepareClient !== "function") fail();
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60 * 60 * 1000) fail();
  const pin = validateReleaseAgreement(release);
  const canaries = ROLES.flatMap((role) => {
    if (!Array.isArray(secretCanaries[role]) || secretCanaries[role].some((entry) => typeof entry !== "string" || entry.length === 0)) fail();
    return [...Object.values(modelEnvironment[role]), ...secretCanaries[role]];
  });
  let run;
  const children = [];
  let timer;
  try {
    run = await createFreshAgentRun({ parent });
    const prepared = {};
    for (const role of ROLES) {
      const client = cleanClient(clients[role]);
      const env = childEnvironment(run.roles[role], modelEnvironment[role]);
      const claudeSessionId = client === "claude" ? randomUUID() : undefined;
      const commands = buildClientCommands({ client, claudeSessionId, manifestDigest: pin.manifestDigest, prompt: "configured later", workspace: run.roles[role].workspace });
      const configure = commands.configure;
      traceLifecycle({ phase: "configure", role, client, status: "started" });
      await configureClient(Object.freeze({ client, command: configure, env, role, room: run.roles[role] }));
      traceLifecycle({ phase: "configure", role, client, status: "completed" });
      if (client === "claude") {
        traceLifecycle({ phase: "prepare", role, client, status: "started" });
        const ready = await prepareClient(Object.freeze({ client, command: commands.prepare, env, role, room: run.roles[role] }));
        if (ready !== true) fail();
        traceLifecycle({ phase: "prepare", role, client, status: "completed" });
      }
      prepared[role] = { claudeSessionId, client, env };
    }
    const timedOut = new Promise((_, rejectPromise) => {
      timer = setTimeout(() => {
        children.forEach(killProcessGroup);
        rejectPromise(new Error("Fresh agent compatibility check failed safely."));
      }, timeoutMs);
    });
    const initiatorCommands = buildClientCommands({
      client: prepared.initiator.client,
      claudeSessionId: prepared.initiator.claudeSessionId,
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
    traceLifecycle({ phase: "spawn", role: "initiator" });
    const initiatorObserved = observeChild(initiatorChild, "initiator", children, canaries, {
      manifestDigest: pin.manifestDigest,
      requireInvitation: true,
    });
    sendPrompt(initiatorChild, initiatorCommands.launch.input);
    const actualInvitation = await Promise.race([
      initiatorObserved.invitation,
      initiatorObserved.result.then(() => fail()),
      timedOut,
    ]);
    const responderCommands = buildClientCommands({
      client: prepared.responder.client,
      claudeSessionId: prepared.responder.claudeSessionId,
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
    traceLifecycle({ phase: "spawn", role: "responder" });
    const responderObserved = observeChild(responderChild, "responder", children, canaries, {
      expectedInvitation: actualInvitation,
      manifestDigest: pin.manifestDigest,
    });
    sendPrompt(responderChild, responderCommands.launch.input);
    const results = await Promise.race([
      Promise.all([initiatorObserved.result, responderObserved.result]),
      timedOut,
    ]);
    clearTimeout(timer);
    timer = undefined;
    const [initiatorProof, responderProof] = results;
    if (initiatorProof.sessionId !== responderProof.sessionId) fail();
    const monitorResult = validateMonitorResult(await monitor({ sessionId: initiatorProof.sessionId }), initiatorProof.sessionId);
    const initiator = publicRole(initiatorProof, monitorResult);
    const responder = publicRole(responderProof, monitorResult);
    if (initiator.address === responder.address || initiator.erc8004.agentId === responder.erc8004.agentId || initiator.policyDigest === responder.policyDigest) fail();
    const evidence = Object.freeze({
      schema: EVIDENCE_SCHEMA,
      runId: run.runId,
      release: pin,
      clients: Object.freeze({ ...clients }),
      roles: Object.freeze({ initiator, responder }),
      monitor: Object.freeze({ chronology: monitorResult.chronology, sessionId: monitorResult.sessionId }),
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
    if (run !== undefined) await rm(run.root, { recursive: true, force: true }).catch(() => {});
  }
}
