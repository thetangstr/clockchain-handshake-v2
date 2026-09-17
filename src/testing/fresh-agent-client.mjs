import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join, relative, resolve } from "node:path";

import { digestHex } from "../core/canonical.mjs";
import { assertSecretFree } from "../core/redact.mjs";
import { validateAgentHandshakeReleasePin } from "../../scripts/verify-agent-handshake-release.mjs";
import {
  CONTINUATION_TOOL_BY_OPERATION,
  createCheckpointCompletionHandler,
  createStreamableMcpClient,
  ROLE_ACCESS_HANDLE,
  roleAccessBinding,
} from "../harness/checkpoint-completion.mjs";
import {
  ADAPTER_APPROVAL_TOOL,
  ADAPTER_MCP_SERVER,
  ADAPTER_MCP_TOOL,
  createVerifiedReleaseActionRecorder,
  VERIFIED_HELPER_BOOTSTRAP,
} from "../harness/verified-release-action-recorder.mjs";
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
// Claude receives NO Bash grant at all: real CLI preflight evidence proved
// every Bash(command) form — exact or wildcard — also permits shell suffixes
// (; && |), which would be arbitrary command execution. Local actions are
// authorized through the per-role stdio MCP adapter tool instead; MCP tool
// calls cannot carry shell suffixes and the tool accepts zero arguments.
function claudeAdapterTools() {
  return Object.freeze([
    ADAPTER_APPROVAL_TOOL,
    "Read(./manifest.json)",
    "Read(./clockchain-agent-handshake.cjs)",
  ]);
}

// Static allowlist contract check only — this mirrors the observed dontAsk
// rule semantics (each shell-chain segment must independently match a granted
// Bash prefix) but is NOT proof of the real Claude CLI permission engine. The
// authoritative check is runClaudePermissionPreflight, which drives the actual
// binary. This function stays as a cheap unit guard against allowlist edits.
export function evaluateClaudeBashPermission(command, tools = claudeAdapterTools()) {
  if (typeof command !== "string" || command.trim().length === 0) return false;
  const grants = tools
    .filter((tool) => tool.startsWith("Bash(") && tool.endsWith(")"))
    .map((tool) => tool.slice(5, -1));
  const segments = command.split(/\r?\n|&&|\|\||[;|&]/).map((entry) => entry.trim()).filter((entry) => entry.length > 0);
  if (segments.length === 0) return false;
  return segments.every((segment) => {
    if (/[$`<>]/.test(segment)) return false;
    return grants.some((grant) => (
      grant.endsWith("*") ? segment.startsWith(grant.slice(0, -1)) : segment === grant
    ));
  });
}

// The probes used by both the static contract check and the real Claude CLI
// preflight. The marker env var names a throwaway file: the stub adapter
// executable and stub MCP server write it only when actually executed, and
// every Bash probe carries a marker-writing suffix so a wrongly-allowed shell
// command is detected by side effect, never by model prose. Probes carry no
// credentials, invitations, or payload material.
const CLAUDE_PERMISSION_PROBE_DIGEST = "0".repeat(64);
const CLAUDE_PREFLIGHT_MARKER_ENV = "CLOCKCHAIN_PREFLIGHT_MARKER";
const CLAUDE_PREFLIGHT_BASH_MARKER_ENV = "CLOCKCHAIN_PREFLIGHT_BASH_MARKER";
const CLAUDE_PERMISSION_PROBES = Object.freeze({
  allowed: Object.freeze([
    Object.freeze({ kind: "mcp_tool" }),
  ]),
  denied: Object.freeze([
    // Every denied probe must be side-effect authoritative: the command itself
    // (or the stub executable it invokes) writes the Bash-only marker iff a
    // shell actually ran it. A probe without a marker write cannot distinguish
    // "denied" from "model never attempted".
    Object.freeze({ kind: "bash", command: `echo probe > "$${CLAUDE_PREFLIGHT_BASH_MARKER_ENV}"` }),
    Object.freeze({ kind: "bash", command: "clockchain-agent-authorize" }),
    Object.freeze({ kind: "bash", command: `printf executed > "$${CLAUDE_PREFLIGHT_BASH_MARKER_ENV}"` }),
    Object.freeze({ kind: "bash", command: `echo probe; printf executed > "$${CLAUDE_PREFLIGHT_BASH_MARKER_ENV}"` }),
    Object.freeze({ kind: "bash", command: `clockchain-agent-authorize; printf executed > "$${CLAUDE_PREFLIGHT_BASH_MARKER_ENV}"` }),
    Object.freeze({ kind: "bash", command: `./.clockchain-adapter/bin/clockchain-agent-authorize; printf executed > "$${CLAUDE_PREFLIGHT_BASH_MARKER_ENV}"` }),
    Object.freeze({ kind: "bash", command: `node .clockchain-adapter/mcp-server.cjs; printf executed > "$${CLAUDE_PREFLIGHT_BASH_MARKER_ENV}"` }),
    // Simulated-only: a real model may ignore the argument instruction and
    // call the tool cleanly, which is not evidence about the boundary. The
    // generated server's malformed-input rejection is proven deterministically
    // in the recorder test suite against the real server.
    Object.freeze({ kind: "mcp_tool_args", simulatedOnly: true, arguments: Object.freeze({ digest: CLAUDE_PERMISSION_PROBE_DIGEST }) }),
  ]),
});

// Cheap static guard over the allowlist contract: the grant list must be
// exactly the adapter MCP tool plus the two pinned-asset Read grants (no Bash,
// no Edit/Write, nothing else), and every modeled Bash probe must be denied.
// Asserts our modeled semantics only — deterministic evidence about the real
// binary comes from runClaudePermissionPreflight.
export function assertClaudeAdapterPermissionContract(tools = claudeAdapterTools()) {
  const expected = new Set(claudeAdapterTools());
  const report = Object.freeze({
    adapterToolGranted: tools.includes(ADAPTER_APPROVAL_TOOL),
    denied: Object.freeze(CLAUDE_PERMISSION_PROBES.denied
      .filter((probe) => probe.kind === "bash")
      .map((probe) => Object.freeze({ command: probe.command, granted: evaluateClaudeBashPermission(probe.command, tools) }))),
    grants: Object.freeze([...tools]),
    unexpected: Object.freeze(tools.filter((tool) => !expected.has(tool))),
  });
  if (
    !report.adapterToolGranted || report.unexpected.length !== 0 ||
    report.denied.some((entry) => entry.granted) ||
    tools.some((tool) => tool.startsWith("Bash(") || tool === "Bash")
  ) fail();
  return report;
}

// Real Claude CLI permission preflight: spawns the actual binary with the same
// launch flags, cwd, PATH layout, permission mode, and allowedTools list used
// by canary runs, and asks it to run each probe once. The stub adapter writes
// a marker file at a nonsecret env-provided path when it actually executes, so
// the outcome is authoritative regardless of stream format or model prose —
// the stdout stream is parsed only to classify denial categories. No
// credentials are exercised, no handshake is performed, and nothing secret is
// retained: the report records per-probe expected/observed outcomes and denied
// tool categories only.
// Stub local MCP server used by both real-client preflights. The marker path
// is embedded literally because Codex filters child-server environment, so an
// env-var-only marker could be stripped; the env var remains as an override.
function stubAdapterMcpServer(markerPath) {
  return `"use strict";
const { writeFileSync } = require("node:fs");
const { createInterface } = require("node:readline");
const TOOL = "authorize_local_action";
const MARKER = process.env.CLOCKCHAIN_PREFLIGHT_MARKER || ${JSON.stringify(markerPath)};
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
createInterface({ input: process.stdin, terminal: false }).on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m === null || typeof m !== "object" || m.id === undefined || m.id === null) return;
  if (m.method === "initialize") return send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "clockchain-local-adapter", version: "preflight" } } });
  if (m.method === "ping") return send({ jsonrpc: "2.0", id: m.id, result: {} });
  if (m.method === "tools/list") return send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: TOOL, inputSchema: { type: "object", properties: {}, additionalProperties: false } }] } });
  if (m.method === "tools/call") {
    const p = m.params || {};
    const clean = p.name === TOOL && (p.arguments === undefined || (typeof p.arguments === "object" && !Array.isArray(p.arguments) && p.arguments !== null && Object.keys(p.arguments).length === 0));
    if (clean && MARKER) { try { writeFileSync(MARKER, "executed"); } catch { /* marker optional */ } }
    return send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: clean ? "ok" : "rejected" }], isError: !clean } });
  }
  return send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "method not found" } });
});
`;
}

function runBoundedChild(spawnProcess, file, args, options, timeoutMs) {
  return new Promise((resolvePromise) => {
    let child;
    try {
      child = spawnProcess(file, args, { ...options, stdio: ["ignore", "pipe", "pipe"], detached: true });
    } catch {
      resolvePromise({ code: null, timedOut: false });
      return;
    }
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolvePromise(result);
    };
    const timer = setTimeout(() => {
      terminateProcessGroup(child);
      for (const stream of [child.stdin, child.stdout, child.stderr]) {
        try { stream?.destroy?.(); } catch { /* already closed */ }
      }
      finish({ code: null, timedOut: true });
    }, timeoutMs);
    child.stdout?.resume?.();
    child.stderr?.resume?.();
    child.once("error", () => finish({ code: null, timedOut: false }));
    child.once("close", (code) => finish({ code: code ?? null, timedOut: false }));
  });
}

// Real Codex proof that the zero-input adapter tool is auto-approved under the
// exact production launch shape. The filesystem marker written by the stub MCP
// server is authoritative; timeout and spawn errors fail, never pass.
export async function runCodexAdapterPreflight({
  cwd,
  env = {},
  executable = "codex",
  manifestDigest,
  spawnProcess = spawn,
  timeoutMs = 120_000,
} = {}) {
  const workspace = absolute(cwd);
  if (!SHA256.test(manifestDigest)) fail();
  if (typeof env !== "object" || env === null || Array.isArray(env)) fail();
  if (typeof executable !== "string" || executable.length === 0 || !SAFE_SEGMENT.test(basename(executable))) fail();
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 10 * 60 * 1000) fail();
  const adapterRoot = join(workspace, ".clockchain-adapter");
  // Per-invocation nonce-scoped marker: the stub embeds this exact path (Codex
  // filters child-server env), so a marker can only be produced by this run's
  // server. A stale marker from any prior run can never satisfy this check.
  const markerPath = join(workspace, `.clockchain-preflight-marker-${randomUUID()}`);
  await rm(markerPath, { force: true });
  await mkdir(adapterRoot, { recursive: true });
  await writeFile(join(adapterRoot, "mcp-server.cjs"), stubAdapterMcpServer(markerPath), { mode: 0o600 });
  const prompt = `Call the MCP tool "${ADAPTER_MCP_TOOL}" provided by the MCP server "${ADAPTER_MCP_SERVER}" exactly once with no arguments, then reply DONE.`;
  const commands = buildClientCommands({ client: "codex", manifestDigest, prompt, workspace });
  const childEnv = {
    ...env,
    CLOCKCHAIN_PREFLIGHT_MARKER: markerPath,
    PATH: env.PATH ?? process.env.PATH ?? "/usr/bin:/bin",
  };
  for (const command of commands.configure) {
    const configureResult = await runBoundedChild(
      spawnProcess, command.file, command.args,
      { cwd: workspace, env: childEnv },
      Math.min(timeoutMs, 30_000),
    );
    if (configureResult.code !== 0 || configureResult.timedOut) {
      return Object.freeze({
        pass: false,
        probes: Object.freeze([Object.freeze({
          command: `configure:${command.args.slice(0, 3).join(" ")}`,
          expected: "allowed",
          observed: configureResult.timedOut ? "timeout" : "configure_failed",
          pass: false,
        })]),
      });
    }
  }
  const child = spawnProcess(executable, commands.launch.args, {
    cwd: workspace,
    env: childEnv,
    stdio: ["pipe", "pipe", "pipe"],
    // Own process group so timeout cleanup can SIGKILL the CLI and any stdio
    // MCP descendants that would otherwise hold pipes open.
    detached: true,
  });
  const outcome = await new Promise((resolvePromise) => {
    let settled = false;
    let attempted = false;
    let denied = false;
    let lineBuffer = "";
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      terminateProcessGroup(child);
      for (const stream of [child.stdin, child.stdout, child.stderr]) {
        try { stream?.destroy?.(); } catch { /* already closed */ }
      }
      resolvePromise({ observed: "timeout" });
    }, timeoutMs);
    function settle(observed) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolvePromise({ observed });
    }
    child.stdout?.on("data", (chunk) => {
      lineBuffer += Buffer.from(chunk).toString("utf8");
      const lines = lineBuffer.split(/\r?\n/);
      lineBuffer = lines.pop() ?? "";
      for (const line of lines) {
        if (line.trim().length === 0) continue;
        let event;
        try { event = JSON.parse(line); } catch { continue; }
        const item = event?.item ?? event?.msg?.item;
        if (item?.type === "mcp_tool_call" || item?.type === "mcpToolCall") {
          const tool = [item?.tool, item?.name].find((value) => typeof value === "string");
          if (tool === ADAPTER_MCP_TOOL || tool === `mcp__${ADAPTER_MCP_SERVER}__${ADAPTER_MCP_TOOL}`) {
            attempted = true;
            const status = typeof item?.status === "string" ? item.status : "";
            if (item?.error !== undefined && item?.error !== null) denied = true;
            if (/approv|denied|fail/i.test(status) && status !== "completed") denied = true;
          }
        }
        const errorText = [event?.error?.message, event?.msg?.error?.message, event?.msg?.message]
          .find((value) => typeof value === "string");
        if (typeof errorText === "string" && /requires approval|approval policy/i.test(errorText)) denied = true;
      }
    });
    child.once("error", () => settle("spawn_error"));
    child.once("close", () => {
      const executed = existsSync(markerPath);
      if (executed && !denied) settle("allowed");
      else if (!executed && denied) settle("denied");
      else if (executed && denied) settle("conflicted");
      else settle(attempted ? "attempted_failed" : "not_attempted");
    });
    child.stdin?.end?.(prompt);
  });
  return Object.freeze({
    pass: outcome.observed === "allowed",
    probes: Object.freeze([Object.freeze({
      command: `mcp_tool:${ADAPTER_MCP_TOOL}`,
      expected: "allowed",
      observed: outcome.observed,
      pass: outcome.observed === "allowed",
    })]),
  });
}

export async function runClaudePermissionPreflight({
  cwd,
  env = {},
  executable = "claude",
  manifestDigest,
  spawnProcess = spawn,
  timeoutMs = 120_000,
} = {}) {
  const workspace = absolute(cwd);
  if (!SHA256.test(manifestDigest)) fail();
  if (typeof env !== "object" || env === null || Array.isArray(env)) fail();
  if (typeof executable !== "string" || executable.length === 0 || !SAFE_SEGMENT.test(basename(executable))) fail();
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 10 * 60 * 1000) fail();
  const adapterRoot = join(workspace, ".clockchain-adapter");
  const adapterBin = join(adapterRoot, "bin");
  const markerPath = join(workspace, ".clockchain-preflight-marker");
  await mkdir(adapterBin, { recursive: true });
  // Stub executable: proves a Bash-launched adapter run by marker side effect.
  // It writes the dedicated BASH marker so a model that substitutes the
  // (legitimately granted) adapter MCP tool cannot make a denied shell probe
  // look executed — the two side effects are distinct files.
  await writeFile(
    join(adapterBin, "clockchain-agent-authorize"),
    "#!/bin/sh\n[ -n \"$CLOCKCHAIN_PREFLIGHT_BASH_MARKER\" ] && printf 'executed' > \"$CLOCKCHAIN_PREFLIGHT_BASH_MARKER\"\n",
    { mode: 0o700 },
  );
  // Stub local MCP server at the exact path the launch args advertise: proves
  // a real authorize_local_action call by marker side effect, and rejects any
  // non-empty arguments without executing.
  await writeFile(
    join(adapterRoot, "mcp-server.cjs"),
    stubAdapterMcpServer(markerPath),
    { mode: 0o600 },
  );
  const probePrompt = (probe) => {
    if (probe.kind === "mcp_tool") {
      return `Call the MCP tool "${ADAPTER_MCP_TOOL}" provided by the MCP server "${ADAPTER_MCP_SERVER}" exactly once with no arguments, then reply DONE.`;
    }
    if (probe.kind === "mcp_tool_args") {
      return `Call the MCP tool "${ADAPTER_MCP_TOOL}" provided by the MCP server "${ADAPTER_MCP_SERVER}" exactly once with these arguments: ${JSON.stringify(probe.arguments)}. Then reply DONE.`;
    }
    return `Use the Bash tool to run exactly this command once, then reply DONE.\n\n${probe.command}`;
  };
  // simulatedOnly probes exercise stream classification with a fake spawner;
  // they are skipped when driving the real binary because their outcome would
  // depend on model compliance rather than the permission boundary.
  const realRun = spawnProcess === spawn;
  const probes = [
    ...CLAUDE_PERMISSION_PROBES.allowed.map((probe) => ({ probe, expected: "allowed" })),
    ...CLAUDE_PERMISSION_PROBES.denied.map((probe) => ({ probe, expected: "denied" })),
  ].filter(({ probe }) => !probe.simulatedOnly || !realRun);
  const bashMarkerPath = join(workspace, ".clockchain-preflight-bash-marker");
  const results = [];
  for (const { probe, expected } of probes) {
    await rm(markerPath, { force: true });
    await rm(bashMarkerPath, { force: true });
    const probeMarker = probe.kind === "bash" ? bashMarkerPath : markerPath;
    const prompt = probePrompt(probe);
    const launch = buildClientCommands({ client: "claude", manifestDigest, prompt, workspace }).launch;
    const child = spawnProcess(executable, launch.args, {
      cwd: workspace,
      env: {
        ...env,
        CLOCKCHAIN_PREFLIGHT_MARKER: markerPath,
        CLOCKCHAIN_PREFLIGHT_BASH_MARKER: bashMarkerPath,
        PATH: `${adapterBin}:${env.PATH ?? process.env.PATH ?? "/usr/bin:/bin"}`,
      },
      stdio: ["pipe", "pipe", "pipe"],
      // Own process group so timeout cleanup can SIGKILL the CLI and any
      // stdio MCP descendants that would otherwise hold pipes open.
      detached: true,
    });
    const outcome = await new Promise((resolvePromise) => {
      let settled = false;
      let attempted = false;
      const deniedTools = new Set();
      const toolNames = new Map();
      let lineBuffer = "";
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        terminateProcessGroup(child);
        for (const stream of [child.stdin, child.stdout, child.stderr]) {
          try { stream?.destroy?.(); } catch { /* already closed */ }
        }
        resolvePromise({ deniedTools: [...deniedTools].sort(), observed: "timeout" });
      }, timeoutMs);
      function settle(observed) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolvePromise({ deniedTools: [...deniedTools].sort(), observed });
      }
      child.stdout?.on("data", (chunk) => {
        lineBuffer += Buffer.from(chunk).toString("utf8");
        const lines = lineBuffer.split(/\r?\n/);
        lineBuffer = lines.pop() ?? "";
        for (const line of lines) {
          if (line.trim().length === 0) continue;
          let event;
          try { event = JSON.parse(line); } catch { continue; }
          for (const key of ["permission_denials", "permissionDenials"]) {
            const denials = event?.[key];
            if (!Array.isArray(denials)) continue;
            for (const entry of denials) {
              const tool = [entry?.tool, entry?.tool_name, entry?.name].find((value) => typeof value === "string" && SAFE_SEGMENT.test(value));
              if (tool !== undefined) deniedTools.add(tool);
            }
          }
          if (event?.type === "assistant" && Array.isArray(event?.message?.content)) {
            for (const block of event.message.content) {
              if (block?.type === "tool_use" && typeof block?.name === "string") {
                if (typeof block.id === "string") toolNames.set(block.id, block.name);
                if (block.name === "Bash" || block.name === ADAPTER_APPROVAL_TOOL) attempted = true;
              }
            }
          }
          if (event?.type === "user" && Array.isArray(event?.message?.content)) {
            for (const block of event.message.content) {
              if (block?.type !== "tool_result" || block.is_error !== true) continue;
              const name = toolNames.get(block.tool_use_id);
              const text = toolResultText(block);
              if (name === "Bash" && /permission|denied|not allowed|disallowed|unavailable|not permitted|unknown tool/i.test(text)) deniedTools.add("Bash");
              if (name === ADAPTER_APPROVAL_TOOL && block.is_error === true) deniedTools.add("adapter_tool");
            }
          }
        }
      });
      child.once("error", () => settle("spawn_error"));
      child.once("close", () => {
        const executed = existsSync(probeMarker);
        if (deniedTools.size > 0 && !executed) settle("denied");
        else if (executed && deniedTools.size === 0) settle("allowed");
        else if (executed && deniedTools.size > 0) settle("conflicted");
        else settle(attempted ? "attempted_unknown" : "not_attempted");
      });
      child.stdin?.end?.(prompt);
    });
    results.push(Object.freeze({
      command: probe.kind === "bash" ? probe.command : `${probe.kind}:${ADAPTER_MCP_TOOL}`,
      deniedTools: Object.freeze(outcome.deniedTools),
      expected,
      observed: outcome.observed,
      pass: expected === "allowed"
        // Allowed probes pass only when the MCP-only marker exists.
        ? outcome.observed === "allowed"
        // Denied probes pass only when the Bash-only marker is absent AND the
        // probe itself bounded cleanly — timeout and spawn_error are failures,
        // not ambiguous evidence.
        : ["denied", "attempted_unknown", "not_attempted"].includes(outcome.observed),
    }));
  }
  return Object.freeze({ probes: Object.freeze(results), pass: results.every((entry) => entry.pass) });
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
  const adapterServerPath = join(cwd, ".clockchain-adapter", "mcp-server.cjs");
  if (clean === "codex") {
    return Object.freeze({
      configure: Object.freeze([
        Object.freeze({
          args: Object.freeze(["mcp", "add", "clockchain-handshake", "--url", CLOCKCHAIN_HANDSHAKE_MCP_URL]),
          file: "codex",
        }),
        Object.freeze({
          args: Object.freeze(["mcp", "add", ADAPTER_MCP_SERVER, "--", process.execPath, adapterServerPath]),
          file: "codex",
        }),
      ]),
      launch: Object.freeze({
        args: Object.freeze([
          "exec", "--skip-git-repo-check", "--strict-config", "--ignore-rules", "--ephemeral",
          "--sandbox", "workspace-write", "--config", 'approval_policy="never"',
          "--config", `mcp_servers.${ADAPTER_MCP_SERVER}.tools.${ADAPTER_MCP_TOOL}.approval_mode="approve"`,
          "--config", "sandbox_workspace_write.network_access=true", "--json", "--cd", cwd, "-",
        ]),
        file: "codex",
        input: prompt,
        limitation: "Codex workspace-write does not provide literal command-pattern enforcement.",
      }),
    });
  }
  return Object.freeze({
    configure: Object.freeze([
      Object.freeze({
        args: Object.freeze(["mcp", "add", "--transport", "http", "--scope", "user", "clockchain-handshake", CLOCKCHAIN_HANDSHAKE_MCP_URL]),
        file: "claude",
      }),
    ]),
    launch: Object.freeze({
      args: Object.freeze([
        "--print", "--bare", "--disable-slash-commands", "--no-chrome",
        "--strict-mcp-config", "--mcp-config", JSON.stringify({
          mcpServers: {
            "clockchain-handshake": { type: "http", url: CLOCKCHAIN_HANDSHAKE_MCP_URL },
            [ADAPTER_MCP_SERVER]: { type: "stdio", command: process.execPath, args: [adapterServerPath] },
          },
        }),
        "--permission-mode", "dontAsk",
        // Defense in depth: even if a Bash grant were ever added back to
        // allowedTools, shell/editing tools stay denied at launch.
        "--disallowedTools", "Bash,Edit,Write,NotebookEdit",
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

// Extracts display text from a Claude tool_result block: content may be a
// plain string or an array of text blocks depending on the CLI version.
function toolResultText(block) {
  if (typeof block?.content === "string") return block.content;
  if (!Array.isArray(block?.content)) return "";
  return block.content.map((part) => (typeof part?.text === "string" ? part.text : "")).join(" ");
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

// Records every helper step from a trusted (adapter completion) Clockchain
// result into the retained-action recorder. Unlike the model-visible stream
// path, a step claiming the counterpart role is corrupt state — it is
// rejected rather than skipped. Returns the number of steps enqueued.
export function recordTrustedHelperSteps(result, { record, role }) {
  if (typeof record !== "function" || !ROLES.includes(role)) fail();
  let count = 0;
  for (const step of collectHelperSteps(result)) {
    if (
      step !== null && typeof step === "object" && !Array.isArray(step) &&
      ROLES.includes(step.role) && step.role !== role
    ) fail();
    record(step);
    count += 1;
  }
  return count;
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

// Preflight cleanup: SIGKILL the whole detached process group so a hung CLI
// or a lingering stdio MCP descendant cannot retain pipes past the deadline.
function terminateProcessGroup(child) {
  try {
    if (Number.isSafeInteger(child?.pid) && child.pid > 0) {
      process.kill(-child.pid, "SIGKILL");
      return;
    }
    child?.kill?.("SIGKILL");
  } catch {
    try { child?.kill?.("SIGKILL"); } catch { /* already exited */ }
  }
}

// Secret-safe per-child metadata: counts, event types, bare Clockchain tool
// names, bounded protocol scalars (stage/needed/localAction operation), the
// last adapter operation, tool-result failure state, and permission-denied
// tool categories — never raw lines, arguments, payloads, or credential
// material. Safe to retain in run artifacts.
function childDiagnostic({
  adapterCompletion, client, code, eventTypes, lastAdapterOperation,
  lastMcpLocalActionOperation, lastMcpNeeded, lastMcpStage,
  lastMcpToolResultFailed, nonJsonLines, observed, permissionDeniedTools,
  signal, stderrBytes, stdoutLines, terminalObserved, toolNames,
}) {
  return Object.freeze({
    adapterCompletion,
    client: typeof client === "string" ? client : null,
    exitCode: Number.isSafeInteger(code) ? code : null,
    exitSignal: typeof signal === "string" ? signal : null,
    invitationObserved: observed.invitation !== undefined,
    lastAdapterOperation,
    lastMcpLocalActionOperation,
    lastMcpNeeded,
    lastMcpStage,
    lastMcpToolResultFailed,
    mcpToolNames: Object.freeze([...toolNames].sort()),
    modelTerminalObserved: observed.terminal !== undefined,
    nonJsonStdoutLines: nonJsonLines,
    permissionDeniedTools: Object.freeze([...permissionDeniedTools].sort()),
    stderrBytes,
    stdoutLines,
    terminalObserved: terminalObserved === true,
    topLevelEventTypes: Object.freeze([...eventTypes].sort()),
  });
}

// Extracts bounded protocol scalars from a completed Clockchain MCP tool
// result value (object, JSON-bearing string, or content-block array). Only
// stage/needed/localAction.operation strings are kept — never payloads.
function scanMcpResultFields(value, found, depth = 0) {
  if (depth > 4) return;
  if (typeof value === "string") {
    const parsed = parseJsonString(value);
    if (parsed !== null) scanMcpResultFields(parsed, found, depth + 1);
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value) scanMcpResultFields(entry, found, depth + 1);
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value)) {
    if ((key === "stage" || key === "needed") && typeof entry === "string" && entry.length <= 64 && SAFE_SEGMENT.test(entry)) {
      found[key] = entry;
      continue;
    }
    if (key === "localAction" && entry !== null && typeof entry === "object" && !Array.isArray(entry)) {
      const operation = entry.operation;
      if (typeof operation === "string" && operation.length <= 64 && SAFE_SEGMENT.test(operation)) found.localActionOperation = operation;
    }
    scanMcpResultFields(entry, found, depth + 1);
  }
}

const ADAPTER_COMPLETION_STATES = Object.freeze(["none", "running", "accepted", "failed"]);

// Wraps a per-role checkpoint completion handler so the close diagnostic can
// report the adapter completion outcome: none until invoked, accepted when the
// handler resolves, failed when it throws. Only the bounded operation name is
// retained — never the completion argv, stateDir, result, or payloads.
export function trackAdapterCompletion(handler, state) {
  if (typeof handler !== "function") fail();
  if (state === null || typeof state !== "object" || Array.isArray(state)) fail();
  return async (completion) => {
    const operation = completion?.operation;
    // A new completion supersedes the last outcome — reset every derived
    // field so a mid-flight snapshot never reports a stale accepted state.
    state.operation =
      typeof operation === "string" && operation.length <= 64 && SAFE_SEGMENT.test(operation)
        ? operation : null;
    state.state = "running";
    state.continuation = null;
    state.advanceCalls = null;
    state.advanceElapsedMs = null;
    state.advanceError = null;
    state.advanceStage = null;
    try {
      const result = await handler(completion);
      state.state = "accepted";
      state.continuation = CONTINUATION_TOOL_BY_OPERATION[operation] ?? null;
      return result;
    } catch (error) {
      state.state = "failed";
      throw error;
    }
  };
}

// Resolves a closing child's terminal proof. Only the trusted
// verify-certificate completion (adapterCompletion.trustedTerminal)
// establishes proof — model text never does. A model-emitted terminal object
// is tolerated only when it is canonically identical to the already
// established trusted proof; anything else fails closed.
export function resolveTerminalProof({ adapterCompletion, invitationObserved = true, modelTerminal, requireInvitation = false } = {}) {
  const trusted = adapterCompletion?.trustedTerminal ?? null;
  if (trusted === null || (requireInvitation && invitationObserved !== true)) fail();
  if (modelTerminal !== undefined && digestHex(modelTerminal) !== digestHex(trusted)) fail();
  return trusted;
}

function observeChild(child, role, all, canaries, { adapter, adapterCompletion, client, onDiagnostic, requireInvitation = false } = {}) {
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
    let stderrBytes = 0;
    let stdoutLines = 0;
    let nonJsonLines = 0;
    let lineBuffer = "";
    let observed = {};
    let settled = false;
    let lastAdapterOperation = null;
    let lastMcpLocalActionOperation = null;
    let lastMcpNeeded = null;
    let lastMcpStage = null;
    let lastMcpToolResultFailed = null;
    const claudeMcpToolCalls = new Map();
    const eventTypes = new Set();
    const permissionDeniedTools = new Set();
    const toolNames = new Set();
    // Emits a sanitized snapshot of everything observed so far. Called
    // synchronously inside reject() (before peers are killed) so the caller
    // has metadata the moment runFreshAgentHandshake rejects — a killed child
    // may never close. The close/error path calls this again so the retained
    // entry is overwritten with the final exit code/signal.
    function emitDiagnostic(code, signal) {
      if (typeof onDiagnostic !== "function") return;
      onDiagnostic(role, childDiagnostic({
        adapterCompletion: Object.freeze({
          advanceCalls: Number.isSafeInteger(adapterCompletion?.advanceCalls) ? adapterCompletion.advanceCalls : null,
          advanceElapsedMs: Number.isSafeInteger(adapterCompletion?.advanceElapsedMs) ? adapterCompletion.advanceElapsedMs : null,
          advanceError: typeof adapterCompletion?.advanceError === "string" && adapterCompletion.advanceError.length <= 32 ? adapterCompletion.advanceError : null,
          advanceStage: typeof adapterCompletion?.advanceStage === "string" && adapterCompletion.advanceStage.length <= 64 ? adapterCompletion.advanceStage : null,
          continuation: typeof adapterCompletion?.continuation === "string" ? adapterCompletion.continuation : null,
          operation: typeof adapterCompletion?.operation === "string" ? adapterCompletion.operation : null,
          state: ADAPTER_COMPLETION_STATES.includes(adapterCompletion?.state) ? adapterCompletion.state : "none",
        }),
        client, code, eventTypes, lastAdapterOperation, lastMcpLocalActionOperation,
        lastMcpNeeded, lastMcpStage, lastMcpToolResultFailed, nonJsonLines, observed,
        terminalObserved: adapterCompletion?.trustedTerminal !== null && adapterCompletion?.trustedTerminal !== undefined,
        permissionDeniedTools, signal, stderrBytes, stdoutLines, toolNames,
      }));
    }
    function processLine(line) {
      if (line.trim().length === 0) return;
      stdoutLines += 1;
      let event;
      try { event = JSON.parse(line); } catch { nonJsonLines += 1; fail(); }
      if (typeof event?.type === "string") eventTypes.add(event.type);
      for (const key of ["permission_denials", "permissionDenials"]) {
        const denials = event?.[key];
        if (!Array.isArray(denials)) continue;
        for (const entry of denials) {
          const tool = [entry?.tool, entry?.tool_name, entry?.name].find((value) => typeof value === "string" && SAFE_SEGMENT.test(value));
          if (tool !== undefined) permissionDeniedTools.add(tool);
        }
      }
      recordClaudeMcpToolCalls(event, claudeMcpToolCalls);
      for (const toolName of claudeMcpToolCalls.values()) toolNames.add(toolName);
      if (
        event?.type === "item.completed" && event?.item?.type === "mcp_tool_call" &&
        mcpToolName(event.item) !== null
      ) {
        toolNames.add(mcpToolName(event.item));
        lastMcpToolResultFailed = event.item.status !== "completed";
      }
      if (event?.type === "user" && Array.isArray(event?.message?.content)) {
        for (const block of event.message.content) {
          if (
            block?.type === "tool_result" && typeof block.tool_use_id === "string" &&
            claudeMcpToolCalls.has(block.tool_use_id)
          ) lastMcpToolResultFailed = block.is_error === true;
        }
      }
      bindCompletedRoleAccess(event, claudeMcpToolCalls, adapter, role);
      for (const value of completedMcpToolResults(event, claudeMcpToolCalls)) {
        const fields = {};
        scanMcpResultFields(value, fields);
        if (fields.stage !== undefined) lastMcpStage = fields.stage;
        if (fields.needed !== undefined) lastMcpNeeded = fields.needed;
        if (fields.localActionOperation !== undefined) lastMcpLocalActionOperation = fields.localActionOperation;
        for (const step of collectHelperSteps(value)) {
          if (
            step !== null && typeof step === "object" && !Array.isArray(step) &&
            ROLES.includes(step.role) && step.role !== role
          ) continue;
          if (typeof step?.operation === "string" && HELPER_OPERATIONS.includes(step.operation)) {
            lastAdapterOperation = step.operation;
          }
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
      all.forEach((peer) => peer.__freshAgentDiagnose?.());
      all.forEach(killProcessGroup);
      const error = new Error("Fresh agent compatibility check failed safely.");
      rejectInvitation?.(error);
      rejectPromise(error);
    }
    child.__freshAgentDiagnose = () => emitDiagnostic(null, null);
    child.stdout?.on("data", (chunk) => { try { processChunk(chunk); } catch { reject(); } });
    child.stderr?.on("data", (chunk) => {
      try { stderrBytes += Buffer.byteLength(chunk); stderr = append(stderr, chunk); } catch { reject(); }
    });
    child.once("error", () => { emitDiagnostic(null, null); reject(); });
    child.stdin?.once?.("error", reject);
    child.once("close", (code, signal) => {
      child.__freshAgentClosed = true;
      emitDiagnostic(code, signal);
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
        resolvePromise(resolveTerminalProof({
          adapterCompletion,
          invitationObserved: observed.invitation !== undefined,
          modelTerminal: observed.terminal,
          requireInvitation,
        }));
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
  diagnostics,
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
  if (diagnostics !== undefined && (diagnostics === null || typeof diagnostics !== "object" || Array.isArray(diagnostics))) fail();
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
      const adapterCompletion = {
        advanceCalls: null, advanceElapsedMs: null, advanceError: null, advanceStage: null,
        operation: null, state: "none", trustedTerminal: null,
      };
      const completionBinding = createCheckpointCompletionHandler({
        checkpointState,
        getCheckpointClient,
        onAdvance: ({ calls, elapsedMs, error, stage }) => {
          adapterCompletion.advanceCalls = calls;
          adapterCompletion.advanceElapsedMs = elapsedMs;
          adapterCompletion.advanceError = error;
          adapterCompletion.advanceStage = stage;
        },
        // The trusted verify-certificate completion is the sole terminal
        // proof source; the model's output is never consulted for it.
        onTerminal: (proof) => {
          adapterCompletion.trustedTerminal = validateTerminal(proof, role);
        },
        // Trusted-channel continuation results (join/next/submit) are not
        // model-visible; newly issued helper steps must still stage through
        // the same recorder so the adapter executes them in order.
        recordSteps: (result) => recordTrustedHelperSteps(result, { record: recorder.record, role }),
      });
      recorder.setCompletionHandler(trackAdapterCompletion(completionBinding.handler, adapterCompletion));
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
      for (const command of configure) {
        await configureClient(Object.freeze({ client, command, env, role, room: adapterRoom }));
      }
      prepared[role] = { adapter, adapterCompletion, client, env };
    }
    // Static allowlist contract guard before any Claude launch. This asserts
    // only the modeled grant semantics; the authoritative permission check is
    // runClaudePermissionPreflight against the real Claude binary.
    if (ROLES.some((role) => prepared[role].client === "claude")) assertClaudeAdapterPermissionContract();
    const timedOut = new Promise((_, rejectPromise) => {
      timer = setTimeout(() => {
        children.forEach((peer) => peer.__freshAgentDiagnose?.());
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
    const recordDiagnostic = diagnostics === undefined ? undefined : (role, meta) => { diagnostics[role] = meta; };
    const initiatorObserved = observeChild(initiatorChild, "initiator", children, canaries, { adapter: prepared.initiator.adapter, adapterCompletion: prepared.initiator.adapterCompletion, client: prepared.initiator.client, onDiagnostic: recordDiagnostic, requireInvitation: true });
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
    const responderObserved = observeChild(responderChild, "responder", children, canaries, { adapter: prepared.responder.adapter, adapterCompletion: prepared.responder.adapterCompletion, client: prepared.responder.client, onDiagnostic: recordDiagnostic });
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
