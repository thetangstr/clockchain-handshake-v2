import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync, randomUUID, sign as signBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { chmod, mkdir, realpath, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { StringDecoder } from "node:string_decoder";

import { assertSecretFree } from "../core/redact.mjs";
import { preparePrivateDirectory, readPrivateText, writePrivateFile } from "../core/private-path.mjs";
import {
  agentHandshakeV2ResultDigest,
  verifyAgentHandshakeV2Result,
} from "../agent-handshake/v2/result.mjs";
import {
  ed25519PublicKeyFingerprint,
  hostSessionKeyCertificateDigest,
} from "../agent-handshake/v2/host-key-certificate.mjs";
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
export const CLAUDE_AUTHENTICATION_MODES = Object.freeze(["disposable", "existing_login_isolated"]);
export const CLOCKCHAIN_HANDSHAKE_TOOLS = Object.freeze([
  "agent_handshake_invite",
  "agent_handshake_accept_invitation",
  "agent_handshake_join",
  "agent_handshake_status",
  "agent_handshake_next",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);
export const VERIFIED_HELPER_BOOTSTRAP = 'const fs=require("node:fs");const crypto=require("node:crypto");const Module=require("node:module");const argv=process.argv.slice(1);const expected=argv.shift();const manifestPath=argv.shift();const helperPath=argv.shift();const manifestBytes=fs.readFileSync(manifestPath);const manifestDigest=crypto.createHash("sha256").update(manifestBytes).digest("hex");if(manifestDigest!==expected)process.exit(86);const manifest=JSON.parse(manifestBytes);if(manifest.schema!=="clockchain.agent-handshake-release-manifest/v1"||manifest.version!=="2.1.2"||!/^24\\./.test(manifest.nodeRuntime)||!/^24\\./.test(process.versions.node)||!Array.isArray(manifest.assets)||manifest.assets.length!==1)process.exit(86);const asset=manifest.assets[0];if(asset.filename!=="clockchain-agent-handshake.cjs"||asset.url!=="https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.2/clockchain-agent-handshake.cjs"||typeof asset.sha256!=="string"||!/^[0-9a-f]{64}$/.test(asset.sha256))process.exit(86);const helperBytes=fs.readFileSync(helperPath);const helperDigest=crypto.createHash("sha256").update(helperBytes).digest("hex");if(helperDigest!==asset.sha256)process.exit(86);process.argv=[process.execPath].concat(helperPath).concat(argv);const loaded=new Module(helperPath);loaded.filename=helperPath;loaded.paths=[];const compile=loaded._compile.bind(loaded);compile(...[helperBytes.toString("utf8")].concat(helperPath));';

const SAFE_SEGMENT = /^[A-Za-z0-9._-]+$/;
const SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const PUBLIC_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const TX = /^0x[0-9a-f]{64}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
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
const ATTEMPT_ARTIFACT_SCHEMA = "clockchain.fresh-agent-canary-attempt/v1";
const RESPONDER_INVITATION_PLACEHOLDER = "<PASTE THE INITIATOR INVITATION>";
const HELPER_CERTIFICATE_BINDINGS = new WeakMap();
export const CLAUDE_CONTEXT_MARKER = "CLOCKCHAIN_CONTEXT_RECEIVED";
export const CLAUDE_CONTEXT_PROMPT = `I am using this fresh disposable workspace for an expected Clockchain test. In my next message I will provide a concrete role-specific request. Do not perform any action now; evaluate that later request on its own exact scope and safety boundaries. Reply exactly ${CLAUDE_CONTEXT_MARKER}.`;
const TRACE_LIFECYCLE = process.env.CLOCKCHAIN_FRESH_AGENT_TRACE === "1";
const DIAGNOSTIC_PHASES = Object.freeze(new Set([
  "agent-exit", "configure", "invitation", "monitor", "preflight", "prepare", "timeout", "unknown",
]));
const DIAGNOSTIC_CATEGORIES = Object.freeze(new Set([
  "agent", "authentication", "client", "deadline", "http", "monitor", "process", "runtime", "unknown", "validation",
]));
const DIAGNOSTIC_CODES = Object.freeze(new Set([
  "AGENT_EXIT", "AGENT_FAILED", "AGENT_OUTPUT_INVALID", "CONFIGURE_FAILED", "HELPER_PROOF_MISSING",
  "HELPER_COMMAND_MISMATCH", "HELPER_EXECUTION_FAILED",
  "INVALID_RETRY_DELAY", "INVALID_TIMEOUT", "INVITATION_MISSING", "MONITOR_FAILED", "MONITOR_RESULT_INVALID",
  "NODE24_REQUIRED", "PREPARE_FAILED", "AUTHENTICATION_FAILED", "TIMEOUT", "UNKNOWN",
]));

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

function traceEventTransportShape(line) {
  const lineBytes = Buffer.byteLength(line);
  let event;
  try { event = JSON.parse(line); } catch {
    return Object.freeze({ lineBytes, parseable: false });
  }
  const content = Array.isArray(event?.message?.content) ? event.message.content : [];
  return Object.freeze({
    lineBytes,
    parseable: true,
    type: typeof event?.type === "string" ? event.type.slice(0, 64) : null,
    subtype: typeof event?.subtype === "string" ? event.subtype.slice(0, 64) : null,
    itemType: typeof event?.item?.type === "string" ? event.item.type.slice(0, 64) : null,
    blockTypes: Object.freeze(content.slice(0, 32).map((block) => typeof block?.type === "string" ? block.type.slice(0, 64) : null)),
    toolNames: Object.freeze(content.slice(0, 32).map((block) => typeof block?.name === "string" ? block.name.slice(0, 64) : null)),
  });
}

export class FreshAgentDiagnosticError extends Error {
  constructor({ phase = "unknown", category = "unknown", code = "UNKNOWN", details } = {}) {
    super("Fresh agent compatibility check failed safely.");
    this.name = "FreshAgentDiagnosticError";
    const cleanCode = cleanDiagnosticCode(code);
    const cleanDetails = cleanHelperDiagnosticDetails(cleanCode, details);
    this.diagnostic = Object.freeze({
      phase: cleanDiagnosticPhase(phase),
      category: cleanDiagnosticCategory(category),
      code: cleanCode,
      ...(cleanDetails === null ? {} : { details: cleanDetails }),
    });
  }

  toJSON() {
    return { name: this.name, message: this.message, diagnostic: this.diagnostic };
  }
}

function cleanDiagnosticPhase(value) {
  return DIAGNOSTIC_PHASES.has(value) ? value : "unknown";
}

function cleanDiagnosticCategory(value) {
  return DIAGNOSTIC_CATEGORIES.has(value) ? value : "unknown";
}

function cleanDiagnosticCode(value) {
  return DIAGNOSTIC_CODES.has(value) || /^HTTP_[1-5][0-9]{2}$/.test(value) ? value : "UNKNOWN";
}

function cleanCommandDiagnostic(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([
    "commandLength", "commandSha256", "operation", "role", "sessionId",
  ])) return null;
  if (
    !Number.isSafeInteger(value.commandLength) || value.commandLength < 1 || value.commandLength > MAX_OUTPUT_BYTES ||
    !SHA256.test(value.commandSha256) || !HELPER_OPERATIONS.includes(value.operation) ||
    !(value.role === null || ROLES.includes(value.role)) ||
    !(value.sessionId === null || UUID.test(value.sessionId))
  ) return null;
  return Object.freeze({
    commandSha256: value.commandSha256,
    commandLength: value.commandLength,
    operation: value.operation,
    role: value.role,
    sessionId: value.sessionId,
  });
}

function cleanHelperDiagnosticDetails(code, value) {
  if (!["HELPER_COMMAND_MISMATCH", "HELPER_EXECUTION_FAILED"].includes(code)) return null;
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(["actual", "expected"])) return null;
  const expected = cleanCommandDiagnostic(value.expected);
  const actual = cleanCommandDiagnostic(value.actual);
  return expected === null || actual === null ? null : Object.freeze({ expected, actual });
}

function diagnostic(phase, category, code, details) {
  return new FreshAgentDiagnosticError({ phase, category, code, details });
}

function fail(phase = "unknown", category = "unknown", code = "UNKNOWN", details) {
  throw diagnostic(phase, category, code, details);
}

export function assertFreshAgentNodeRuntime({
  execPath = process.execPath,
  version = process.versions.node,
} = {}) {
  if (typeof execPath !== "string" || !isAbsolute(execPath) || resolve(execPath) !== execPath) {
    fail("preflight", "runtime", "NODE24_REQUIRED");
  }
  const cleanVersion = typeof version === "string" && version.startsWith("v") ? version.slice(1) : version;
  if (typeof cleanVersion !== "string" || !/^24\./.test(cleanVersion)) {
    fail("preflight", "runtime", "NODE24_REQUIRED");
  }
  return Object.freeze({
    execPath,
    pathDirectory: dirname(execPath),
    version: cleanVersion,
  });
}

function diagnosticFrom(error, phase, category, code) {
  if (error instanceof FreshAgentDiagnosticError) return error;
  return diagnostic(phase, category, code);
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

function cleanAuthenticationMode(client, value) {
  if (client === "codex") {
    if (value !== "disposable") fail();
    return value;
  }
  if (!CLAUDE_AUTHENTICATION_MODES.includes(value)) fail();
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

function stripLiteralShellLineContinuations(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024 * 1024) fail();
  let quote = null;
  let normalized = "";
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (quote === "single") {
      if (char === "'") quote = null;
      normalized += char;
      continue;
    }
    if (quote === "double") {
      if (char === '"') {
        quote = null;
        normalized += char;
      }
      else if (char === "\\" && value[index + 1] === "\n") index += 1;
      else {
        if (char === "\\" || char === "`" || char === "\r") fail();
        normalized += char;
      }
      continue;
    }
    if (char === "\\" && value[index + 1] === "\n") {
      index += 1;
      continue;
    }
    if (/\s/.test(char)) {
      normalized += char;
      continue;
    }
    if (char === "'") {
      quote = "single";
      normalized += char;
      continue;
    }
    if (char === '"') {
      quote = "double";
      normalized += char;
      continue;
    }
    normalized += char;
  }
  if (quote !== null) fail();
  return normalized;
}

function parseLiteralShellWords(value) {
  value = stripLiteralShellLineContinuations(value);
  const words = [];
  let quote = null;
  let word = "";
  let started = false;
  for (const char of value) {
    if (quote === "single") {
      if (char === "'") quote = null;
      else word += char;
      continue;
    }
    if (quote === "double") {
      if (char === '"') quote = null;
      else {
        if (char === "\\" || char === "`" || char === "\r") fail();
        word += char;
      }
      continue;
    }
    if (/\s/.test(char)) {
      if (started) {
        words.push(word);
        word = "";
        started = false;
      }
      continue;
    }
    if (char === "'") {
      quote = "single";
      started = true;
      continue;
    }
    if (char === '"') {
      quote = "double";
      started = true;
      continue;
    }
    if (char === "\\" || /[;&|<>`()[\]{}*?!#~$]/.test(char)) fail();
    word += char;
    started = true;
  }
  if (quote !== null) fail();
  if (started) words.push(word);
  return words;
}

function splitCodexCommandDisplay(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024 * 1024) fail();
  const words = [];
  let current = "";
  let started = false;
  let quote = null;
  let quotedLength = 0;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (quote === "single") {
      if (char === "'") quote = null;
      else {
        if (char === "\\" || (char === "^" && quotedLength !== 0)) fail();
        current += char;
        quotedLength += 1;
      }
      continue;
    }
    if (quote === "double") {
      if (char === '"') {
        quote = null;
        continue;
      }
      if (char === "\\") {
        const next = value[index + 1];
        if (next === undefined || !['"', "\\"].includes(next)) fail();
        index += 1;
        current += next;
        continue;
      }
      if (["$", "`", "!", "^"].includes(char)) fail();
      current += char;
      continue;
    }
    if (/\s/.test(char)) {
      if (started) {
        words.push(current);
        current = "";
        started = false;
      }
      continue;
    }
    if (char === "'") {
      quote = "single";
      quotedLength = 0;
      started = true;
      continue;
    }
    if (char === '"') {
      quote = "double";
      quotedLength = 0;
      started = true;
      continue;
    }
    if (char === "\\" || !/^[+\-.\/:@\]_0-9A-Za-z]$/.test(char)) fail();
    current += char;
    started = true;
  }
  if (quote !== null) fail();
  if (started) words.push(current);
  return words;
}

export function unwrapCodexCommandExecution(value) {
  if (typeof value !== "string" || value !== value.trim() || !value.startsWith("/bin/zsh -c ")) fail();
  const words = splitCodexCommandDisplay(value);
  if (words.length !== 3 || words[0] !== "/bin/zsh" || words[1] !== "-c" || words[2].length === 0) fail();
  return words[2];
}

export function fingerprintHelperExecutionCommand(value) {
  const shape = classifyHelperExecutionCommand(value);
  const stateMatch = value.match(new RegExp(`\\.clockchain/handshakes/(${UUID.source.slice(1, -1)})/(initiator|responder)(?=[\\s"']|$)`));
  let request = null;
  if (shape.operation === "sign") {
    const payloadMatch = value.match(/--payload-base64url\s+([A-Za-z0-9_-]+)/);
    if (payloadMatch !== null) {
      let bytes;
      let parsed;
      try {
        bytes = Buffer.from(payloadMatch[1], "base64url");
        parsed = JSON.parse(bytes.toString("utf8"));
      } catch {
        bytes = Buffer.alloc(0);
        parsed = null;
      }
      const record = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
      request = Object.freeze({
        bytesSha256: SHA256.test(record.bytesSha256) ? record.bytesSha256 : null,
        encodingCanonical: bytes.length > 0 && bytes.toString("base64url") === payloadMatch[1],
        helperVersion: typeof record.helperVersion === "string" ? record.helperVersion : null,
        jsonSha256: createHash("sha256").update(bytes).digest("hex"),
        operation: typeof record.operation === "string" ? record.operation : null,
        policyDigest: SHA256.test(record.policyDigest) ? record.policyDigest : null,
        role: ROLES.includes(record.role) ? record.role : null,
        schema: typeof record.schema === "string" ? record.schema : null,
        sessionId: UUID.test(record.sessionId) ? record.sessionId : null,
      });
    }
  }
  return Object.freeze({
    ...shape,
    commandSha256: createHash("sha256").update(value, "utf8").digest("hex"),
    request,
    state: stateMatch === null ? null : Object.freeze({ sessionId: stateMatch[1], role: stateMatch[2] }),
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

export function buildClientCommands({
  client,
  claudeAuthenticationMode = "disposable",
  claudeSessionId,
  hostHome = homedir(),
  hostUid = process.getuid?.(),
  manifestDigest,
  prompt,
  workspace,
} = {}) {
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
          "--config", "allow_login_shell=false",
          "--config", "sandbox_workspace_write.network_access=true", "--json", "--cd", cwd, "-",
        ]),
        file: "codex",
        input: prompt,
        limitation: "Codex workspace-write does not provide literal command-pattern enforcement.",
      }),
    });
  }
  const authenticationMode = cleanAuthenticationMode(clean, claudeAuthenticationMode);
  if (!UUID.test(claudeSessionId)) fail();
  const sandboxSettings = buildClaudeSandboxSettings({ hostHome, hostUid, workspace: cwd });
  const existingLoginIsolated = authenticationMode === "existing_login_isolated";
  return Object.freeze({
    configure: Object.freeze({
      args: Object.freeze(existingLoginIsolated
        ? ["auth", "status"]
        : ["mcp", "add", "--transport", "http", "--scope", "user", "clockchain-handshake", CLOCKCHAIN_HANDSHAKE_MCP_URL]),
      file: "claude",
    }),
    prepare: Object.freeze({
      args: Object.freeze(existingLoginIsolated ? [
        "--print", "--model", "sonnet", "--effort", "low", "--no-session-persistence",
        "--disable-slash-commands", "--no-chrome", "--permission-mode", "dontAsk",
        "--setting-sources", "", "--tools", "", "--output-format", "json",
      ] : [
        "--print", "--model", "sonnet", "--effort", "low", "--session-id", claudeSessionId,
        "--disable-slash-commands", "--no-chrome", "--permission-mode", "dontAsk",
        "--setting-sources", "", "--output-format", "json",
      ]),
      file: "claude",
      input: CLAUDE_CONTEXT_PROMPT,
    }),
    launch: Object.freeze({
      args: Object.freeze([
        "--print", existingLoginIsolated ? "--session-id" : "--resume", claudeSessionId,
        "--model", "sonnet", "--effort", "high",
        ...(existingLoginIsolated ? ["--no-session-persistence"] : []),
        "--disable-slash-commands", "--no-chrome",
        "--strict-mcp-config", "--mcp-config", JSON.stringify({
          mcpServers: { "clockchain-handshake": { type: "http", url: CLOCKCHAIN_HANDSHAKE_MCP_URL } },
        }),
        "--permission-mode", "dontAsk",
        "--setting-sources", "",
        "--settings", JSON.stringify(sandboxSettings),
        "--output-format", "stream-json",
        "--verbose",
        "--tools", "Bash,Read,ToolSearch",
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

function adapterExecutable(runtimeExecPath, publicKeyDer) {
  return `#!${runtimeExecPath}\n` + String.raw`"use strict";
const { spawnSync } = require("node:child_process");
const { createPublicKey, verify } = require("node:crypto");
const { mkdirSync, readFileSync, renameSync, rmSync } = require("node:fs");
const { dirname, join, resolve } = require("node:path");
function stop() { process.exit(86); }
const digest = process.argv.length === 3 ? process.argv[2] : "";
if (!/^[0-9a-f]{64}$/.test(digest)) stop();
const root = dirname(dirname(__filename));
const pending = join(root, "pending", digest + ".json");
const running = join(root, "running", digest + "." + process.pid + ".json");
try { renameSync(pending, running); } catch { stop(); }
try {
  const envelope = JSON.parse(readFileSync(running, "utf8"));
  if (!envelope || Object.keys(envelope).sort().join(",") !== "body,schema,signature" || envelope.schema !== "clockchain.agent-harness-bound-action/v1") stop();
  const bodyBytes = Buffer.from(JSON.stringify(envelope.body), "utf8");
  const key = createPublicKey({ key: Buffer.from("${publicKeyDer}", "base64"), format: "der", type: "spki" });
  if (!verify(null, bodyBytes, key, Buffer.from(envelope.signature, "base64"))) stop();
  const body = envelope.body;
  if (!body || Object.keys(body).sort().join(",") !== "args,commandLength,commandSha256,cwd,file,operation,role,schema,sessionId,stateDir") stop();
  if (body.schema !== "clockchain.agent-harness-bound-action-body/v1" || body.commandSha256 !== digest || !Number.isSafeInteger(body.commandLength)) stop();
  if (body.file !== process.execPath || body.cwd !== process.cwd() || !Array.isArray(body.args) || body.args.some((value) => typeof value !== "string")) stop();
  const tmp = resolve(process.env.TMPDIR || "");
  const state = resolve(body.stateDir);
  if (!tmp || !state.startsWith(tmp + "/")) stop();
  mkdirSync(state, { recursive: true, mode: 0o700 });
  const child = spawnSync(body.file, body.args, { cwd: body.cwd, env: process.env, stdio: "inherit" });
  if (child.error || !Number.isSafeInteger(child.status)) stop();
  process.exitCode = child.status;
} catch { stop(); }
finally { try { rmSync(running, { force: true }); } catch {} }
`;
}

function adapterNodeShim(runtimeExecPath) {
  return `#!${runtimeExecPath}\n` + String.raw`"use strict";
const { spawnSync } = require("node:child_process");
const args = process.argv.slice(2);
if (args[0] === "--input-type=commonjs" && args[1] === "--eval" && args.at(-1) !== "--version") process.exit(86);
const child = spawnSync("${runtimeExecPath}", args, { env: process.env, stdio: "inherit" });
if (child.error || !Number.isSafeInteger(child.status)) process.exit(86);
process.exitCode = child.status;
`;
}

export async function prepareAgentHarnessAdapter({ manifestDigest, room, runtimeExecPath = process.execPath } = {}) {
  if (!SHA256.test(manifestDigest) || room === null || typeof room !== "object" || Array.isArray(room)) fail();
  const workspace = absolute(room.workspace);
  const tmp = descendant(workspace, room.tmp);
  const runtime = absolute(runtimeExecPath);
  const root = join(workspace, ".clockchain-adapter");
  const bin = join(root, "bin");
  const pending = join(root, "pending");
  const running = join(root, "running");
  for (const path of [root, bin, pending, running]) await privateDirectory(path);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const executable = join(bin, "clockchain-agent-authorize");
  await writePrivateFile({ path: executable, bytes: Buffer.from(adapterExecutable(runtime, publicKeyDer), "utf8") });
  await chmod(executable, 0o500);
  const nodeShim = join(bin, "node");
  await writePrivateFile({ path: nodeShim, bytes: Buffer.from(adapterNodeShim(runtime), "utf8") });
  await chmod(nodeShim, 0o500);

  function record(value) {
    const expected = expectedHelperCommand(value);
    if (expected === null || expected.approvalCommand !== `clockchain-agent-authorize ${expected.commandSha256}`) fail();
    const argv = [...expected.argv];
    if (argv[0] !== "node") fail();
    argv[5] = isAbsolute(argv[5]) ? descendant(workspace, argv[5]) : descendant(workspace, resolve(workspace, argv[5]));
    argv[6] = isAbsolute(argv[6]) ? descendant(workspace, argv[6]) : descendant(workspace, resolve(workspace, argv[6]));
    if (typeof argv[9] !== "string" || !argv[9].startsWith("$TMPDIR/")) fail();
    argv[9] = descendant(tmp, resolve(tmp, argv[9].slice("$TMPDIR/".length)));
    validateHelperCommand({ argv, kind: "helper", manifestDigest, workspace });
    const body = Object.freeze({
      schema: "clockchain.agent-harness-bound-action-body/v1",
      commandSha256: expected.commandSha256,
      commandLength: expected.commandLength,
      operation: expected.operation,
      role: expected.role,
      sessionId: expected.sessionId,
      file: runtime,
      args: Object.freeze(argv.slice(1)),
      cwd: workspace,
      stateDir: argv[9],
    });
    const signature = signBytes(null, Buffer.from(JSON.stringify(body), "utf8"), privateKey).toString("base64");
    const bytes = `${JSON.stringify({ schema: "clockchain.agent-harness-bound-action/v1", body, signature })}\n`;
    const target = join(pending, `${expected.commandSha256}.json`);
    try {
      writeFileSync(target, bytes, { encoding: "utf8", flag: "wx", mode: 0o600 });
    } catch (error) {
      if (error?.code !== "EEXIST" || readFileSync(target, "utf8") !== bytes) fail();
    }
    return expected;
  }

  return Object.freeze({ bin, pending, record, root });
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
    !SHA256.test(parsed.statementDigest) || typeof parsed.certificateVerified !== "boolean" ||
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

function validateNonterminalHelperResult(parsed) {
  if (parsed.operation === "init") {
    const item = exactObject(parsed, ["address", "helperVersion", "operation", "schema"]);
    if (item.schema !== HELPER_RESULT_SCHEMA || item.helperVersion !== "2.1.2" || !PUBLIC_ADDRESS.test(item.address)) fail();
    return;
  }
  if (parsed.operation === "policy") {
    const item = exactObject(parsed, ["helperVersion", "operation", "policyDigest", "schema"]);
    if (item.schema !== HELPER_RESULT_SCHEMA || item.helperVersion !== "2.1.2" || !SHA256.test(item.policyDigest)) fail();
    return;
  }
  if (parsed.operation === "inspect") {
    const item = exactObject(parsed, ["address", "helperVersion", "operation", "policyDigest", "registration", "schema"]);
    if (
      item.schema !== HELPER_RESULT_SCHEMA || item.helperVersion !== "2.1.2" ||
      !ADDRESS.test(item.address) || item.policyDigest !== null && !SHA256.test(item.policyDigest)
    ) fail();
    if (item.registration !== null) validateRegistration(item.registration);
    return;
  }
  if (parsed.operation === "register") {
    const item = exactObject(parsed, ["address", "helperVersion", "operation", "registration", "schema"]);
    if (item.schema !== HELPER_RESULT_SCHEMA || item.helperVersion !== "2.1.2" || !ADDRESS.test(item.address)) fail();
    validateRegistration(item.registration);
    return;
  }
  if (parsed.operation === "sign") {
    const item = exactObject(parsed, ["address", "bytesSha256", "helperVersion", "operation", "schema", "signatureHex"]);
    if (
      item.schema !== HELPER_RESULT_SCHEMA || item.helperVersion !== "2.1.2" ||
      !ADDRESS.test(item.address) || !SHA256.test(item.bytesSha256) || !SIGNATURE.test(item.signatureHex)
    ) fail();
    return;
  }
  fail();
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

function inspectEvent(value, role) {
  void role;
  let found = {};
  const pending = [value];
  let visited = 0;
  while (pending.length > 0) {
    visited += 1;
    if (visited > 50_000) fail("agent-exit", "validation", "AGENT_OUTPUT_INVALID");
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
    if (["agent_message", "text"].includes(current.type) && Object.hasOwn(current, "text")) {
      const candidate = invitationMessage(current.text);
      if (candidate !== null) found = mergeObserved(found, { invitation: candidate });
    }
    if (Object.hasOwn(current, "responderInvitation")) {
      found = mergeObserved(found, { invitation: invitation(current.responderInvitation) });
    }
    pending.push(...Object.values(current));
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

function parsedHelperOutput(value, role) {
  if (typeof value !== "string") return Object.freeze({ matched: false, proof: null });
  const parsed = parseJsonString(value);
  if (parsed === null || parsed?.schema !== HELPER_RESULT_SCHEMA) {
    return Object.freeze({ matched: false, proof: null });
  }
  if (parsed.operation !== "verify-certificate") {
    validateNonterminalHelperResult(parsed);
    return Object.freeze({ matched: true, proof: null });
  }
  return Object.freeze({ matched: true, proof: validateHelperProof(parsed, role) });
}

function expectedHelperCommand(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const step = value;
  if (typeof step.shellCommand !== "string" || step.shellCommand.length === 0) return null;
  const fingerprint = fingerprintHelperExecutionCommand(step.shellCommand);
  if (
    fingerprint.operation === null || fingerprint.state === null ||
    (step.operation !== undefined && step.operation !== fingerprint.operation) ||
    (step.role !== undefined && step.role !== fingerprint.state.role) ||
    (step.sessionId !== undefined && step.sessionId !== fingerprint.state.sessionId)
  ) {
    fail("agent-exit", "validation", "AGENT_OUTPUT_INVALID");
  }
  const operation = fingerprint.operation;
  const role = fingerprint.state.role;
  const sessionId = fingerprint.state.sessionId;
  const commandLength = Number.isSafeInteger(step.commandLength)
    ? step.commandLength
    : Buffer.byteLength(step.shellCommand);
  const commandSha256 = typeof step.commandSha256 === "string" && SHA256.test(step.commandSha256)
    ? step.commandSha256
    : createHash("sha256").update(step.shellCommand, "utf8").digest("hex");
  if (
    commandLength !== Buffer.byteLength(step.shellCommand) ||
    commandSha256 !== createHash("sha256").update(step.shellCommand, "utf8").digest("hex")
  ) {
    fail("agent-exit", "validation", "AGENT_OUTPUT_INVALID");
  }
  const approvalCommand = step.approvalCommand === undefined
    ? null
    : step.approvalCommand;
  if (approvalCommand !== null && approvalCommand !== `clockchain-agent-authorize ${commandSha256}`) {
    fail("agent-exit", "validation", "AGENT_OUTPUT_INVALID");
  }
  return Object.freeze({
    approvalCommand,
    argv: Object.freeze(parseLiteralShellWords(step.shellCommand)),
    commandLength,
    commandSha256,
    operation,
    role,
    sessionId,
    shellCommand: step.shellCommand,
  });
}

function collectExpectedHelperCommands(value, found = [], seen = new Set()) {
  if (typeof value === "string") {
    const parsed = parseJsonString(value);
    if (parsed !== null) collectExpectedHelperCommands(parsed, found, seen);
    return found;
  }
  if (value === null || typeof value !== "object") return found;
  if (Array.isArray(value)) {
    for (const entry of value) collectExpectedHelperCommands(entry, found, seen);
    return found;
  }
  const localAction = value.localAction;
  if (localAction !== null && typeof localAction === "object" && !Array.isArray(localAction)) {
    const helperStep = expectedHelperCommand(localAction.helperStep);
    if (helperStep !== null) {
      const key = `${helperStep.commandSha256}:${helperStep.commandLength}`;
      if (!seen.has(key)) {
        seen.add(key);
        found.push(helperStep);
      }
    }
    if (Array.isArray(localAction.helperSteps)) {
      for (const step of localAction.helperSteps) {
        const helper = expectedHelperCommand(step);
        if (helper !== null) {
          const key = `${helper.commandSha256}:${helper.commandLength}`;
          if (!seen.has(key)) {
            seen.add(key);
            found.push(helper);
          }
        }
      }
    }
  }
  for (const entry of Object.values(value)) {
    collectExpectedHelperCommands(entry, found, seen);
  }
  return found;
}

function bindHelperExecution(command, expectedHelperCommands) {
  const expected = expectedHelperCommands[0];
  if (expected === undefined) {
    const actual = fingerprintHelperExecutionCommand(command);
    return Object.freeze({ bound: false, actual });
  }
  const approvalMatches = expected.approvalCommand !== null && command === expected.approvalCommand;
  const helperActual = fingerprintHelperExecutionCommand(command);
  const approvalShaped = command.includes("clockchain-agent-authorize");
  if (!approvalShaped && helperActual.operation === null) {
    return Object.freeze({ bound: false, actual: helperActual });
  }
  const actual = approvalMatches
    ? Object.freeze({
        ...helperActual,
        operation: expected.operation,
        state: Object.freeze({ role: expected.role, sessionId: expected.sessionId }),
      })
    : helperActual;
  const actualArgv = parseLiteralShellWords(command);
  const argvMatches = actualArgv.length === expected.argv.length &&
    actualArgv.every((entry, index) => entry === expected.argv[index]);
  const rawCommandMatches = actual.commandSha256 === expected.commandSha256 &&
    Buffer.byteLength(command) === expected.commandLength;
  const details = Object.freeze({
    expected: Object.freeze({
      commandSha256: expected.commandSha256,
      commandLength: expected.commandLength,
      operation: expected.operation,
      role: expected.role,
      sessionId: expected.sessionId,
    }),
    actual: Object.freeze({
      commandSha256: actual.commandSha256,
      commandLength: Buffer.byteLength(command),
      operation: actual.operation,
      role: actual.state?.role ?? null,
      sessionId: actual.state?.sessionId ?? null,
    }),
  });
  if (
    (expected.approvalCommand !== null ? !approvalMatches : (!rawCommandMatches && !argvMatches)) ||
    actual.operation !== expected.operation ||
    actual.state?.role !== expected.role ||
    actual.state?.sessionId !== expected.sessionId
  ) {
    traceLifecycle({ phase: "helper-command-mismatch", details });
    fail("agent-exit", "validation", "HELPER_COMMAND_MISMATCH", details);
  }
  return Object.freeze({ bound: true, actual, expected, details });
}

function consumeHelperExecution(binding, expectedHelperCommands) {
  if (!binding.bound) return;
  if (expectedHelperCommands[0] !== binding.expected) fail("agent-exit", "validation", "AGENT_OUTPUT_INVALID");
  expectedHelperCommands.shift();
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
  return Object.freeze({
    certificate: payload.certificate,
    repositorySha: payload.repositorySha,
    sessionDeadlineMs: payload.sessionDeadlineMs,
  });
}

function helperProofFromEvent(event, role, manifestDigest, claudeBashCommands, expectedHelperCommands, helperExecutionState) {
  if (
    event?.type === "item.completed" && event?.item?.type === "command_execution" &&
    typeof event.item.command === "string"
  ) {
    const command = unwrapCodexCommandExecution(event.item.command);
    const binding = bindHelperExecution(command, expectedHelperCommands);
    if (
      binding.bound &&
      (event.item.status === "failed" || (event.item.status === "completed" && event.item.exit_code !== 0))
    ) {
      helperExecutionState.failed = true;
      helperExecutionState.details = binding.details;
    }
    if (event.item.status !== "completed" || event.item.exit_code !== 0) return null;
    const output = parsedHelperOutput(event.item.aggregated_output, role);
    if (binding.bound && !output.matched) fail("agent-exit", "validation", "AGENT_OUTPUT_INVALID");
    consumeHelperExecution(binding, expectedHelperCommands);
    const proof = output.proof;
    if (proof === null) return null;
    const verifiedCommand = binding.bound ? binding.expected.shellCommand : command;
    HELPER_CERTIFICATE_BINDINGS.set(proof, validateVerifyCertificateCommand(verifiedCommand, proof, manifestDigest));
    return proof;
  }
  if (event?.type === "assistant" && Array.isArray(event?.message?.content)) {
    for (const block of event.message.content) {
      if (block?.type !== "tool_use" || block?.name !== "Bash") continue;
      if (typeof block.id !== "string" || block.id.length === 0 || typeof block?.input?.command !== "string") fail();
      if (claudeBashCommands.has(block.id)) fail();
      const command = stripLiteralShellLineContinuations(block.input.command);
      const binding = bindHelperExecution(command, expectedHelperCommands);
      claudeBashCommands.set(block.id, Object.freeze({
        command: binding.bound ? binding.expected.shellCommand : command,
        details: binding.bound ? binding.details : null,
      }));
    }
    return null;
  }
  if (event?.type !== "user" || !Array.isArray(event?.message?.content)) return null;
  let found = null;
  for (const block of event.message.content) {
    if (block?.type !== "tool_result") continue;
    if (block.is_error === true) {
      const execution = typeof block.tool_use_id === "string" ? claudeBashCommands.get(block.tool_use_id) : null;
      if (execution !== null && typeof execution === "object" && typeof execution.command === "string") {
        helperExecutionState.failed = true;
        helperExecutionState.details = execution.details;
        claudeBashCommands.set(block.tool_use_id, null);
      }
      continue;
    }
    const output = parsedHelperOutput(block.content, role);
    if (typeof block.tool_use_id !== "string") {
      if (output.matched) fail();
      continue;
    }
    const execution = claudeBashCommands.get(block.tool_use_id);
    if (execution === undefined) {
      if (output.matched) fail();
      continue;
    }
    if (execution === null || typeof execution !== "object" || typeof execution.command !== "string") fail();
    if (execution.details !== null && !output.matched) fail("agent-exit", "validation", "AGENT_OUTPUT_INVALID");
    if (execution.details !== null) {
      const expected = expectedHelperCommands[0];
      if (
        expected === undefined || expected.commandSha256 !== execution.details.expected.commandSha256 ||
        expected.commandLength !== execution.details.expected.commandLength
      ) fail();
      expectedHelperCommands.shift();
    }
    const parsed = output.proof;
    if (parsed === null) continue;
    const command = execution.command;
    HELPER_CERTIFICATE_BINDINGS.set(parsed, validateVerifyCertificateCommand(command, parsed, manifestDigest));
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

function observeChild(child, role, all, canaries, { adapter, expectedInvitation, manifestDigest, requireInvitation = false } = {}) {
  if (!SHA256.test(manifestDigest)) fail();
  if (adapter === null || typeof adapter !== "object" || typeof adapter.record !== "function") fail();
  let resolveInvitation;
  let rejectInvitation;
  const invitationPromise = requireInvitation ? new Promise((resolvePromise, rejectPromise) => {
    resolveInvitation = resolvePromise;
    rejectInvitation = rejectPromise;
  }) : null;
  const result = new Promise((resolvePromise, rejectPromise) => {
    let stderr = "";
    let lineBuffer = "";
    const stdoutDecoder = new StringDecoder("utf8");
    let rejectedEvent = null;
    let observed = {};
    const claudeBashCommands = new Map();
    const expectedHelperCommands = [];
    const helperExecutionState = { failed: false, details: null };
    let settled = false;
    function processLine(line) {
      if (line.trim().length === 0) return;
      let event;
      try { event = JSON.parse(line); } catch { fail(); }
      const discoveredHelperCommands = collectExpectedHelperCommands(event);
      for (const command of discoveredHelperCommands) {
        if (command.approvalCommand !== null) adapter.record(command);
      }
      expectedHelperCommands.push(...discoveredHelperCommands);
      observed = mergeObserved(observed, inspectEvent(event, role));
      const helperProof = helperProofFromEvent(event, role, manifestDigest, claudeBashCommands, expectedHelperCommands, helperExecutionState);
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
                ? fingerprintHelperExecutionCommand(block.input.command)
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
                ? fingerprintHelperExecutionCommand(unwrapCodexCommandExecution(event.item.command))
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
      lineBuffer += stdoutDecoder.write(Buffer.from(chunk));
      let newlineIndex;
      while ((newlineIndex = lineBuffer.indexOf("\n")) >= 0) {
        const rawLine = lineBuffer.slice(0, newlineIndex);
        lineBuffer = lineBuffer.slice(newlineIndex + 1);
        rejectedEvent = traceEventTransportShape(rawLine);
        if (Buffer.byteLength(rawLine) > MAX_OUTPUT_BYTES) fail();
        const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
        assertSecretFree(line, canaries);
        processLine(line);
        rejectedEvent = null;
      }
      if (Buffer.byteLength(lineBuffer) > MAX_OUTPUT_BYTES) fail();
    }
    function reject(error = diagnostic("agent-exit", "agent", "AGENT_FAILED")) {
      if (settled) return;
      settled = true;
      traceLifecycle({
        phase: "observer-reject",
        role,
        diagnostic: error instanceof FreshAgentDiagnosticError ? error.diagnostic : null,
        bufferedLineBytes: Buffer.byteLength(lineBuffer),
        stderrBytes: Buffer.byteLength(stderr),
        event: rejectedEvent,
      });
      all.forEach(killProcessGroup);
      rejectInvitation?.(error);
      rejectPromise(error);
    }
    child.stdout?.on("data", (chunk) => {
      try { processChunk(chunk); } catch (error) {
        reject(error instanceof FreshAgentDiagnosticError && error.diagnostic.code !== "UNKNOWN"
          ? error
          : diagnostic("agent-exit", "validation", "AGENT_OUTPUT_INVALID"));
      }
    });
    child.stderr?.on("data", (chunk) => {
      try { stderr = append(stderr, chunk); } catch {
        reject(diagnostic("agent-exit", "validation", "AGENT_OUTPUT_INVALID"));
      }
    });
    child.once("error", () => reject(diagnostic("agent-exit", "process", "AGENT_EXIT")));
    child.stdin?.once?.("error", () => reject(diagnostic("agent-exit", "process", "AGENT_EXIT")));
    child.once("close", (code) => {
      traceLifecycle({ phase: "close", role, code: Number.isSafeInteger(code) ? code : null, stderrBytes: Buffer.byteLength(stderr) });
      child.__freshAgentClosed = true;
      if (settled) return;
      settled = true;
      if (code !== 0) {
        const error = diagnostic("agent-exit", "process", "AGENT_EXIT");
        rejectInvitation?.(error);
        return rejectPromise(error);
      }
      try {
        lineBuffer += stdoutDecoder.end();
        if (Buffer.byteLength(lineBuffer) > MAX_OUTPUT_BYTES) fail();
        if (lineBuffer.trim().length > 0) processLine(lineBuffer);
        assertSecretFree(lineBuffer, canaries);
        assertSecretFree(stderr, canaries);
        if (requireInvitation && observed.invitation === undefined) fail("invitation", "agent", "INVITATION_MISSING");
        if (observed.helperProof === undefined) {
          fail(
            "agent-exit",
            "agent",
            helperExecutionState.failed ? "HELPER_EXECUTION_FAILED" : "HELPER_PROOF_MISSING",
            helperExecutionState.details,
          );
        }
        resolvePromise(observed.helperProof);
      } catch (error) {
        error = diagnosticFrom(error, "agent-exit", "validation", "AGENT_OUTPUT_INVALID");
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

const CLAUDE_EXISTING_LOGIN_SESSION_ENV = Object.freeze([
  "LOGNAME",
  "SHELL",
  "SSH_AUTH_SOCK",
  "TERM",
  "USER",
  "XPC_FLAGS",
  "XPC_SERVICE_NAME",
  "__CF_USER_TEXT_ENCODING",
]);

function childEnvironment(room, credentials, runtime, {
  adapterBin,
  authenticationMode = "disposable",
  client,
  hostEnvironment = process.env,
  hostHome = homedir(),
} = {}) {
  if (credentials === null || typeof credentials !== "object" || Array.isArray(credentials)) fail();
  for (const [key, value] of Object.entries(credentials)) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(key) || typeof value !== "string" || value.length === 0) fail();
  }
  const basePath = hostEnvironment.PATH ?? "/usr/bin:/bin";
  const runtimePath = runtime === undefined ? basePath : `${runtime.pathDirectory}:${basePath}`;
  const path = adapterBin === undefined ? runtimePath : `${descendant(room.workspace, adapterBin)}:${runtimePath}`;
  const common = {
    ...credentials,
    CODEX_HOME: room.home,
    CLAUDE_CODE_TMPDIR: room.tmp,
    GIT_CONFIG_NOSYSTEM: "1",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATH: path,
    TMPDIR: room.tmp,
    XDG_CACHE_HOME: room.cache,
  };
  const mode = cleanAuthenticationMode(cleanClient(client), authenticationMode);
  if (client === "claude" && mode === "existing_login_isolated") {
    const sessionEnvironment = {};
    for (const name of CLAUDE_EXISTING_LOGIN_SESSION_ENV) {
      const value = hostEnvironment[name];
      if (typeof value === "string" && value.length > 0) sessionEnvironment[name] = value;
    }
    return Object.freeze({
      ...common,
      ...sessionEnvironment,
      CLAUDE_CODE_DISABLE_AUTO_MEMORY: "1",
      CLAUDE_CODE_DISABLE_BUNDLED_SKILLS: "1",
      CLAUDE_CODE_DISABLE_CLAUDE_MDS: "1",
      CLAUDE_CODE_DISABLE_WORKFLOWS: "1",
      HOME: absolute(hostHome),
    });
  }
  return Object.freeze({
    ...common,
    CLAUDE_CONFIG_DIR: join(room.home, ".claude"),
    HOME: room.home,
  });
}

function validateMonitorRole(value) {
  const item = exactObject(value, ["address", "erc8004", "policyDigest"]);
  if (!ADDRESS.test(item.address) || !SHA256.test(item.policyDigest)) fail();
  return Object.freeze({ address: item.address, policyDigest: item.policyDigest, erc8004: validateRegistration(item.erc8004) });
}

function validateMonitorReceipt(value, kind) {
  const item = exactObject(value, ["blockHeight", "blockTimeRaw", "digest", "explorerUrl", "kind", "ledgerId"]);
  if (
    item.kind !== kind || !DECIMAL.test(item.blockHeight) || typeof item.blockTimeRaw !== "string" ||
    item.blockTimeRaw.length === 0 || !SHA256.test(item.digest) || typeof item.explorerUrl !== "string" ||
    !/^https:\/\//.test(item.explorerUrl) || !UUID.test(item.ledgerId)
  ) fail();
  return Object.freeze({ ...item });
}

function validateMonitorResult(value, expectedSessionId) {
  const item = exactObject(value, [
    "certificate", "checker", "externalBusinessActionPerformed", "hostTrust", "receipts",
    "repositorySha", "roles", "sessionId", "statementDigest", "timing",
  ]);
  const certificate = exactObject(item.certificate, ["digest", "issuedAtMs", "outcome"]);
  const checker = exactObject(item.checker, ["stage", "lastSeenMs"]);
  const hostTrust = exactObject(item.hostTrust, [
    "rootKid", "rootFingerprint", "sessionPublicKey", "sessionKeyCertificateDigest",
  ]);
  const timing = exactObject(item.timing, [
    "createdAtMs", "invitationExpiresAtMs", "sessionDeadlineMs", "agreementValidForSeconds",
  ]);
  if (
    item.sessionId !== expectedSessionId || !UUID.test(item.sessionId) || !SHA.test(item.repositorySha) ||
    !SHA256.test(item.statementDigest) || item.externalBusinessActionPerformed !== false ||
    !SHA256.test(certificate.digest) || certificate.outcome !== "VERIFIED" ||
    !Number.isSafeInteger(certificate.issuedAtMs) || certificate.issuedAtMs < 0 ||
    checker.stage !== "VERIFIED" || !Number.isSafeInteger(checker.lastSeenMs) || checker.lastSeenMs < 0 ||
    typeof hostTrust.rootKid !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(hostTrust.rootKid) ||
    !SHA256.test(hostTrust.rootFingerprint) || typeof hostTrust.sessionPublicKey !== "string" ||
    Buffer.from(hostTrust.sessionPublicKey, "base64").length !== 32 ||
    !SHA256.test(hostTrust.sessionKeyCertificateDigest) ||
    !Number.isSafeInteger(timing.createdAtMs) || !Number.isSafeInteger(timing.invitationExpiresAtMs) ||
    !Number.isSafeInteger(timing.sessionDeadlineMs) || timing.agreementValidForSeconds !== "90"
  ) fail();
  const receipts = exactObject(item.receipts, ["proposal", "acceptance", "acknowledgment"]);
  const roles = exactObject(item.roles, ROLES);
  return Object.freeze({
    certificate: Object.freeze({ ...certificate }),
    checker: Object.freeze({ ...checker }),
    externalBusinessActionPerformed: false,
    hostTrust: Object.freeze({ ...hostTrust }),
    receipts: Object.freeze({
      proposal: validateMonitorReceipt(receipts.proposal, "proposal"),
      acceptance: validateMonitorReceipt(receipts.acceptance, "acceptance"),
      acknowledgment: validateMonitorReceipt(receipts.acknowledgment, "acknowledgment"),
    }),
    repositorySha: item.repositorySha,
    roles: Object.freeze({ initiator: validateMonitorRole(roles.initiator), responder: validateMonitorRole(roles.responder) }),
    sessionId: item.sessionId,
    statementDigest: item.statementDigest,
    timing: Object.freeze({ ...timing }),
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
    certificate: snapshot.certificate,
    checker: snapshot.checker,
    externalBusinessActionPerformed: snapshot.externalBusinessActionPerformed,
    hostTrust: snapshot.hostTrust,
    receipts: snapshot.receipts,
    repositorySha: snapshot.repositorySha,
    roles: Object.fromEntries(ROLES.map((role) => [role, {
      address: snapshot.parties[role].sessionKeyAddress,
      erc8004: snapshot.parties[role].erc8004,
      policyDigest: snapshot.policies[role].digest,
    }])),
    sessionId: snapshot.sessionId,
    statementDigest: agentHandshakeV2StatementDigest(terms),
    timing: snapshot.timing,
  }, expectedSessionId);
}

function publicRole(value, monitorResult, binding) {
  const role = monitorResult.roles[value.role];
  if (
    value.sessionId !== monitorResult.sessionId || value.statementDigest !== monitorResult.statementDigest ||
    value.policyDigest !== role.policyDigest || value.identity.sessionKeyAddress !== role.address ||
    JSON.stringify(value.identity.erc8004) !== JSON.stringify(role.erc8004)
  ) fail();
  return Object.freeze({
    address: role.address,
    certificateDigest: monitorResult.certificate.digest,
    certificateVerified: binding.certificateVerified,
    erc8004: role.erc8004,
    externalBusinessActionPerformed: value.externalBusinessActionPerformed,
    policyDigest: value.policyDigest,
    receiptIds: [
      monitorResult.receipts.proposal.ledgerId,
      monitorResult.receipts.acceptance.ledgerId,
      monitorResult.receipts.acknowledgment.ledgerId,
    ],
    role: value.role,
    sessionId: value.sessionId,
  });
}

function attemptId(value) {
  if (typeof value !== "string" || !SAFE_SEGMENT.test(value)) fail();
  return value;
}

function diagnosticPayload(error) {
  const clean = error instanceof FreshAgentDiagnosticError
    ? error.diagnostic
    : diagnostic("unknown", "unknown", "UNKNOWN").diagnostic;
  const code = cleanDiagnosticCode(clean.code);
  const details = cleanHelperDiagnosticDetails(code, clean.details);
  return Object.freeze({
    phase: cleanDiagnosticPhase(clean.phase),
    category: cleanDiagnosticCategory(clean.category),
    code,
    ...(details === null ? {} : { details }),
  });
}

function validatePublicRoleEvidence(value, role, expectedSessionId, expectedCertificateDigest, expectedCertificateVerified) {
  const item = exactObject(value, [
    "address", "certificateDigest", "certificateVerified", "erc8004", "externalBusinessActionPerformed",
    "policyDigest", "receiptIds", "role", "sessionId",
  ]);
  if (
    item.role !== role || item.sessionId !== expectedSessionId || !ADDRESS.test(item.address) ||
    item.certificateDigest !== expectedCertificateDigest || item.certificateVerified !== expectedCertificateVerified ||
    item.externalBusinessActionPerformed !== false || !SHA256.test(item.policyDigest) ||
    !Array.isArray(item.receiptIds) || item.receiptIds.length !== 3 ||
    new Set(item.receiptIds).size !== 3 || item.receiptIds.some((entry) => !UUID.test(entry))
  ) fail();
  return Object.freeze({
    address: item.address,
    certificateDigest: item.certificateDigest,
    certificateVerified: item.certificateVerified,
    erc8004: validateRegistration(item.erc8004),
    externalBusinessActionPerformed: false,
    policyDigest: item.policyDigest,
    receiptIds: Object.freeze([...item.receiptIds]),
    role,
    sessionId: item.sessionId,
  });
}

function validatePublicMonitorEvidence(value, expectedSessionId, binding) {
  const item = exactObject(value, ["certificate", "checker", "hostTrust", "receipts", "sessionId"]);
  const certificate = exactObject(item.certificate, ["digest", "issuedAtMs", "outcome"]);
  const checker = exactObject(item.checker, ["stage", "lastSeenMs"]);
  const hostTrust = exactObject(item.hostTrust, [
    "rootKid", "rootFingerprint", "sessionPublicKey", "sessionKeyCertificateDigest",
  ]);
  if (
    item.sessionId !== expectedSessionId || certificate.digest !== binding.certificateDigest ||
    certificate.outcome !== "VERIFIED" || !Number.isSafeInteger(certificate.issuedAtMs) || certificate.issuedAtMs < 0 ||
    checker.stage !== "VERIFIED" || !Number.isSafeInteger(checker.lastSeenMs) || checker.lastSeenMs < 0 ||
    !/^[a-z0-9][a-z0-9-]{0,63}$/.test(hostTrust.rootKid) ||
    hostTrust.rootFingerprint !== binding.hostRootFingerprint ||
    typeof hostTrust.sessionPublicKey !== "string" || Buffer.from(hostTrust.sessionPublicKey, "base64").length !== 32 ||
    hostTrust.sessionKeyCertificateDigest !== binding.hostSessionKeyCertificateDigest
  ) fail();
  const receipts = exactObject(item.receipts, ["proposal", "acceptance", "acknowledgment"]);
  return Object.freeze({
    certificate: Object.freeze({ ...certificate }),
    checker: Object.freeze({ ...checker }),
    hostTrust: Object.freeze({ ...hostTrust }),
    receipts: Object.freeze({
      proposal: validateMonitorReceipt(receipts.proposal, "proposal"),
      acceptance: validateMonitorReceipt(receipts.acceptance, "acceptance"),
      acknowledgment: validateMonitorReceipt(receipts.acknowledgment, "acknowledgment"),
    }),
    sessionId: item.sessionId,
  });
}

function validateSuccessEvidence(value) {
  const item = exactObject(value, [
    "binding", "certificateVerified", "cleanup", "clients", "monitor", "release", "roles", "runId", "schema",
  ]);
  if (item.schema !== EVIDENCE_SCHEMA || !SAFE_SEGMENT.test(item.runId) || item.certificateVerified !== true) fail();
  const clients = exactObject(item.clients, ROLES);
  const release = validateReleaseAgreement({ mcp: item.release, research: item.release });
  const binding = exactObject(item.binding, [
    "certificateDigest", "hostRootFingerprint", "hostSessionKeyCertificateDigest", "repositorySha", "sessionDeadlineMs",
  ]);
  if (
    !SHA256.test(binding.certificateDigest) || !SHA256.test(binding.hostRootFingerprint) ||
    !release.hostRoots.includes(binding.hostRootFingerprint) ||
    !SHA256.test(binding.hostSessionKeyCertificateDigest) || !SHA.test(binding.repositorySha) ||
    !Number.isSafeInteger(binding.sessionDeadlineMs) || binding.sessionDeadlineMs < 1
  ) fail();
  const roles = exactObject(item.roles, ROLES);
  const initiator = validatePublicRoleEvidence(roles.initiator, "initiator", item.monitor?.sessionId, binding.certificateDigest, item.certificateVerified);
  const responder = validatePublicRoleEvidence(roles.responder, "responder", item.monitor?.sessionId, binding.certificateDigest, item.certificateVerified);
  if (
    initiator.address === responder.address || initiator.erc8004.agentId === responder.erc8004.agentId ||
    initiator.policyDigest === responder.policyDigest ||
    JSON.stringify(initiator.receiptIds) !== JSON.stringify(responder.receiptIds)
  ) fail();
  const cleanup = exactObject(item.cleanup, ["completed"]);
  if (cleanup.completed !== true) fail();
  return Object.freeze({
    schema: EVIDENCE_SCHEMA,
    runId: item.runId,
    release,
    clients: Object.freeze({ initiator: cleanClient(clients.initiator), responder: cleanClient(clients.responder) }),
    roles: Object.freeze({ initiator, responder }),
    certificateVerified: true,
    binding: Object.freeze({ ...binding }),
    monitor: validatePublicMonitorEvidence(item.monitor, initiator.sessionId, binding),
    cleanup: Object.freeze({ completed: true }),
  });
}

export async function writeFreshAgentAttemptArtifact({
  attemptId: rawAttemptId = randomUUID(),
  directory,
  error,
  evidence,
  outcome,
  secretCanaries = [],
} = {}) {
  const cleanDirectory = absolute(directory);
  const cleanAttemptId = attemptId(rawAttemptId);
  if (!["success", "failure"].includes(outcome)) fail();
  if (!Array.isArray(secretCanaries) || secretCanaries.some((entry) => typeof entry !== "string" || entry.length === 0)) fail();
  const artifact = outcome === "success"
    ? Object.freeze({
        schema: ATTEMPT_ARTIFACT_SCHEMA,
        attemptId: cleanAttemptId,
        outcome,
        result: validateSuccessEvidence(evidence),
      })
    : Object.freeze({
        schema: ATTEMPT_ARTIFACT_SCHEMA,
        attemptId: cleanAttemptId,
        outcome,
        diagnostic: diagnosticPayload(error),
      });
  assertSecretFree(artifact, secretCanaries);
  await preparePrivateDirectory({ path: cleanDirectory });
  const bytes = Buffer.from(`${JSON.stringify(artifact)}\n`, "utf8");
  const target = join(cleanDirectory, `${cleanAttemptId}.json`);
  const written = await writePrivateFile({ path: target, bytes });
  const readback = await readPrivateText({ path: target, maxBytes: bytes.length });
  if (readback !== bytes.toString("utf8")) fail();
  return Object.freeze({ path: written.path, size: written.size });
}

function monitorParty(monitorResult, role) {
  const value = monitorResult.roles[role];
  return Object.freeze({
    sessionKeyAddress: value.address,
    policyDigest: value.policyDigest,
    erc8004: value.erc8004,
  });
}

function verifyParentCertificateBinding({ initiatorProof, monitorResult, pin, responderProof }) {
  const initiator = HELPER_CERTIFICATE_BINDINGS.get(initiatorProof);
  const responder = HELPER_CERTIFICATE_BINDINGS.get(responderProof);
  if (initiator === undefined || responder === undefined) fail();
  if (
    initiator.repositorySha !== responder.repositorySha ||
    initiator.sessionDeadlineMs !== responder.sessionDeadlineMs ||
    initiator.repositorySha !== monitorResult.repositorySha ||
    Number(initiator.sessionDeadlineMs) !== monitorResult.timing.sessionDeadlineMs
  ) fail();
  const initiatorDigest = agentHandshakeV2ResultDigest(initiator.certificate);
  const responderDigest = agentHandshakeV2ResultDigest(responder.certificate);
  if (
    initiatorDigest !== responderDigest ||
    initiatorDigest !== monitorResult.certificate.digest
  ) fail();
  const certificate = initiator.certificate;
  const hostCertificate = certificate.hostSessionKeyCertificate;
  const rootPublicKey = hostCertificate?.rootSignature?.publicKey;
  const rootFingerprint = ed25519PublicKeyFingerprint(rootPublicKey);
  if (
    rootFingerprint !== monitorResult.hostTrust.rootFingerprint ||
    !pin.hostRoots.includes(rootFingerprint) ||
    hostCertificate?.certificate?.rootKid !== monitorResult.hostTrust.rootKid ||
    hostCertificate.certificate.sessionId !== monitorResult.sessionId ||
    hostCertificate.certificate.repositorySha !== monitorResult.repositorySha ||
    hostCertificate.certificate.sessionPublicKey !== monitorResult.hostTrust.sessionPublicKey ||
    hostSessionKeyCertificateDigest(hostCertificate) !== monitorResult.hostTrust.sessionKeyCertificateDigest
  ) fail();
  const rootKeyRing = Object.freeze([Object.freeze({
    kid: hostCertificate.rootSignature.keyId,
    publicKey: rootPublicKey,
    fingerprint: rootFingerprint,
  })]);
  const common = Object.freeze({
    expectedRepositorySha: monitorResult.repositorySha,
    expectedSessionId: monitorResult.sessionId,
    nowMs: monitorResult.certificate.issuedAtMs,
    rootKeyRing,
    sessionDeadlineMs: monitorResult.timing.sessionDeadlineMs,
  });
  for (const [role, proof, binding] of [
    ["initiator", initiatorProof, initiator],
    ["responder", responderProof, responder],
  ]) {
    const verified = verifyAgentHandshakeV2Result(binding.certificate, {
      ...common,
      expectedParty: monitorParty(monitorResult, role),
      expectedPolicyDigest: monitorResult.roles[role].policyDigest,
      expectedRole: role,
    });
    if (
      verified.certificateVerified !== true ||
      verified.externalBusinessActionPerformed !== false ||
      verified.sessionId !== proof.sessionId ||
      verified.role !== proof.role ||
      verified.policyDigest !== proof.policyDigest ||
      verified.statementDigest !== proof.statementDigest ||
      verified.identity.sessionKeyAddress !== proof.identity.sessionKeyAddress ||
      JSON.stringify(verified.identity.erc8004) !== JSON.stringify(proof.identity.erc8004)
    ) fail();
  }
  return Object.freeze({
    binding: Object.freeze({
      certificateDigest: initiatorDigest,
      hostRootFingerprint: rootFingerprint,
      hostSessionKeyCertificateDigest: monitorResult.hostTrust.sessionKeyCertificateDigest,
      repositorySha: monitorResult.repositorySha,
      sessionDeadlineMs: monitorResult.timing.sessionDeadlineMs,
    }),
    certificateVerified: true,
  });
}

export async function runFreshAgentHandshake({
  authenticationModes = { initiator: "disposable", responder: "disposable" },
  clients,
  configureClient,
  modelEnvironment = {},
  secretCanaries = { initiator: [], responder: [] },
  monitor,
  hostEnvironment = process.env,
  hostHome = homedir(),
  parent,
  prepareClient,
  prompts,
  release,
  runtimeExecPath,
  runtimeVersion,
  spawnProcess = spawn,
  timeoutMs = 10 * 60 * 1000,
} = {}) {
  exactObject(authenticationModes, ROLES);
  exactObject(clients, ROLES);
  exactObject(prompts, ROLES);
  exactObject(modelEnvironment, ROLES);
  exactObject(secretCanaries, ROLES);
  if (typeof configureClient !== "function" || typeof monitor !== "function" || typeof prepareClient !== "function") fail();
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60 * 60 * 1000) fail();
  const pin = validateReleaseAgreement(release);
  const runtime = runtimeExecPath === undefined && runtimeVersion === undefined
    ? undefined
    : assertFreshAgentNodeRuntime({ execPath: runtimeExecPath, version: runtimeVersion });
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
      const authenticationMode = cleanAuthenticationMode(client, authenticationModes[role]);
      const adapter = await prepareAgentHarnessAdapter({
        manifestDigest: pin.manifestDigest,
        room: run.roles[role],
        runtimeExecPath: runtime?.execPath ?? process.execPath,
      });
      const env = childEnvironment(run.roles[role], modelEnvironment[role], runtime, {
        adapterBin: adapter.bin,
        authenticationMode,
        client,
        hostEnvironment,
        hostHome,
      });
      const claudeSessionId = client === "claude" ? randomUUID() : undefined;
      const commands = buildClientCommands({
        client,
        claudeAuthenticationMode: authenticationMode,
        claudeSessionId,
        hostHome,
        manifestDigest: pin.manifestDigest,
        prompt: "configured later",
        workspace: run.roles[role].workspace,
      });
      const configure = commands.configure;
      traceLifecycle({ phase: "configure", role, client, status: "started" });
      try {
        await configureClient(Object.freeze({ client, command: configure, env, role, room: run.roles[role] }));
      } catch (error) {
        throw diagnosticFrom(error, "configure", "client", "CONFIGURE_FAILED");
      }
      traceLifecycle({ phase: "configure", role, client, status: "completed" });
      if (client === "claude") {
        traceLifecycle({ phase: "prepare", role, client, status: "started" });
        let ready;
        try {
          ready = await prepareClient(Object.freeze({ client, command: commands.prepare, env, role, room: run.roles[role] }));
        } catch (error) {
          throw diagnosticFrom(error, "prepare", "client", "PREPARE_FAILED");
        }
        if (ready !== true) fail("prepare", "client", "PREPARE_FAILED");
        traceLifecycle({ phase: "prepare", role, client, status: "completed" });
      }
      prepared[role] = { adapter, authenticationMode, claudeSessionId, client, env };
    }
    const timedOut = new Promise((_, rejectPromise) => {
      timer = setTimeout(() => {
        children.forEach(killProcessGroup);
        rejectPromise(diagnostic("timeout", "deadline", "TIMEOUT"));
      }, timeoutMs);
    });
    const initiatorCommands = buildClientCommands({
      client: prepared.initiator.client,
      claudeAuthenticationMode: prepared.initiator.authenticationMode,
      claudeSessionId: prepared.initiator.claudeSessionId,
      hostHome,
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
      adapter: prepared.initiator.adapter,
      manifestDigest: pin.manifestDigest,
      requireInvitation: true,
    });
    sendPrompt(initiatorChild, initiatorCommands.launch.input);
    const actualInvitation = await Promise.race([
      initiatorObserved.invitation,
      initiatorObserved.result.then(() => fail("invitation", "agent", "INVITATION_MISSING")),
      timedOut,
    ]);
    const responderCommands = buildClientCommands({
      client: prepared.responder.client,
      claudeAuthenticationMode: prepared.responder.authenticationMode,
      claudeSessionId: prepared.responder.claudeSessionId,
      hostHome,
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
      adapter: prepared.responder.adapter,
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
    let rawMonitorResult;
    try {
      rawMonitorResult = await monitor({ sessionId: initiatorProof.sessionId });
    } catch (error) {
      throw diagnosticFrom(error, "monitor", "monitor", "MONITOR_FAILED");
    }
    let monitorResult;
    try {
      monitorResult = validateMonitorResult(rawMonitorResult, initiatorProof.sessionId);
    } catch {
      throw diagnostic("monitor", "validation", "MONITOR_RESULT_INVALID");
    }
    let binding;
    try {
      binding = verifyParentCertificateBinding({ initiatorProof, responderProof, monitorResult, pin });
    } catch {
      throw diagnostic("monitor", "validation", "MONITOR_RESULT_INVALID");
    }
    const initiator = publicRole(initiatorProof, monitorResult, binding);
    const responder = publicRole(responderProof, monitorResult, binding);
    if (initiator.address === responder.address || initiator.erc8004.agentId === responder.erc8004.agentId || initiator.policyDigest === responder.policyDigest) fail();
    const evidence = Object.freeze({
      schema: EVIDENCE_SCHEMA,
      runId: run.runId,
      release: pin,
      clients: Object.freeze({ ...clients }),
      roles: Object.freeze({ initiator, responder }),
      certificateVerified: binding.certificateVerified,
      binding: binding.binding,
      monitor: Object.freeze({
        certificate: monitorResult.certificate,
        checker: monitorResult.checker,
        hostTrust: monitorResult.hostTrust,
        receipts: monitorResult.receipts,
        sessionId: monitorResult.sessionId,
      }),
      cleanup: Object.freeze({ completed: true }),
    });
    assertSecretFree(evidence, [...canaries, actualInvitation, run.root]);
    await rm(run.root, { recursive: true, force: true });
    run = undefined;
    return evidence;
  } catch (error) {
    throw diagnosticFrom(error, "unknown", "unknown", "UNKNOWN");
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    children.forEach(killProcessGroup);
    if (run !== undefined) await rm(run.root, { recursive: true, force: true }).catch(() => {});
  }
}
