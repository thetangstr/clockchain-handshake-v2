#!/usr/bin/env node

import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  FreshAgentDiagnosticError,
  runFreshAgentHandshake,
  validateClaudePreparation,
  validateFreshAgentMonitorSnapshot,
} from "../src/testing/fresh-agent-client.mjs";
import {
  installAppleClientAuthentication,
  loadAppleClientAuthentication,
} from "../src/testing/apple-client-auth.mjs";

const execFileAsync = promisify(execFile);
const SAFE_ERROR = "Fresh agent compatibility check failed safely.\n";
const SHA256 = /^[0-9a-f]{64}$/;
const TRANSIENT_MONITOR_STATUSES = new Set([429, 502, 503, 504]);

function safeMonitorError(category, code) {
  return new FreshAgentDiagnosticError({ phase: "monitor", category, code });
}

function failureCategory(value) {
  if (typeof value !== "string") return null;
  const text = value.toLowerCase();
  for (const [category, needles] of [
    ["authentication", ["authentication", "api key", "oauth", "log in", "login"]],
    ["billing", ["credit balance", "billing"]],
    ["model", ["model", "sonnet"]],
    ["permission", ["permission", "denied", "not allowed"]],
    ["rate-limit", ["rate limit", "too many requests"]],
    ["session", ["session"]],
    ["arguments", ["unknown option", "unknown argument", "invalid argument"]],
  ]) {
    if (needles.some((needle) => text.includes(needle))) return category;
  }
  return "other";
}

function value(name) {
  const result = process.env[name];
  if (typeof result !== "string" || result.length === 0) throw new Error("invalid");
  return result;
}

function roots(name) {
  const result = value(name).split(",");
  if (result.length < 1 || result.length > 2 || result.some((entry) => !SHA256.test(entry))) throw new Error("invalid");
  return result;
}

async function authenticationFor(client) {
  const key = client === "codex" ? "OPENAI_API_KEY" : "ANTHROPIC_API_KEY";
  const credential = process.env[key];
  if (typeof credential === "string" && credential.length > 0) {
    return Object.freeze({
      client,
      environment: Object.freeze({ [key]: credential }),
      secretCanaries: Object.freeze([credential]),
      source: null,
    });
  }
  const override = client === "codex" ? "CLOCKCHAIN_CODEX_AUTH_FILE" : "CLOCKCHAIN_CLAUDE_AUTH_FILE";
  const source = process.env[override] ?? join(homedir(), client === "codex" ? ".codex/auth.json" : ".claude/.credentials.json");
  return loadAppleClientAuthentication({ client, source });
}

async function configureClient({ authentication, command, env, room }) {
  if (typeof authentication.source === "string" || typeof authentication.serialized === "string") {
    await installAppleClientAuthentication({ authentication, home: room.home });
  }
  await execFileAsync(command.file, command.args, {
    env,
    maxBuffer: 64 * 1024,
    timeout: 30_000,
    windowsHide: true,
  });
}

async function prepareClient({ authentication, command, env, room }) {
  let stdout;
  try {
    ({ stdout } = await execFileAsync(command.file, [...command.args, command.input], {
      cwd: room.workspace,
      env,
      maxBuffer: 1024 * 1024,
      timeout: 60_000,
      windowsHide: true,
    }));
  } catch (error) {
    if (process.env.CLOCKCHAIN_FRESH_AGENT_TRACE === "1") {
      process.stderr.write(`${JSON.stringify({
        phase: "prepare-process",
        client: "claude",
        code: Number.isSafeInteger(error?.code) ? error.code : null,
        signal: typeof error?.signal === "string" ? error.signal : null,
        killed: error?.killed === true,
        stdoutBytes: typeof error?.stdout === "string" ? Buffer.byteLength(error.stdout) : 0,
        stderrBytes: typeof error?.stderr === "string" ? Buffer.byteLength(error.stderr) : 0,
        stdoutCategory: failureCategory(error?.stdout),
        stderrCategory: failureCategory(error?.stderr),
      })}\n`);
    }
    throw error;
  }
  return validateClaudePreparation(stdout, authentication.secretCanaries);
}

export async function monitor({ sessionId, retryDelayMs = 1_000, timeoutMs = 120_000 } = {}) {
  const endpoint = value("CLOCKCHAIN_RESEARCH_MONITOR_URL");
  if (!Number.isSafeInteger(retryDelayMs) || retryDelayMs < 1 || retryDelayMs > 60_000) throw safeMonitorError("validation", "INVALID_RETRY_DELAY");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60 * 60 * 1000) throw safeMonitorError("validation", "INVALID_TIMEOUT");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let response;
    try {
      response = await fetch(endpoint, { cache: "no-store" });
    } catch {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, Math.min(retryDelayMs, Math.max(0, deadline - Date.now()))));
      continue;
    }
    if (!response.ok) {
      const status = Number.isSafeInteger(response.status) ? response.status : 0;
      if (!TRANSIENT_MONITOR_STATUSES.has(status)) throw safeMonitorError("http", `HTTP_${status}`);
      await new Promise((resolvePromise) => setTimeout(resolvePromise, Math.min(retryDelayMs, Math.max(0, deadline - Date.now()))));
      continue;
    }
    const completed = validateFreshAgentMonitorSnapshot(await response.json(), sessionId);
    if (completed !== null) return completed;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, Math.min(retryDelayMs, Math.max(0, deadline - Date.now()))));
  }
  throw safeMonitorError("deadline", "TIMEOUT");
}

async function main() {
  const prompts = JSON.parse(await readFile(new URL("../test/fixtures/fresh-agent/prompts.json", import.meta.url), "utf8"));
  const clients = {
    initiator: process.env.CLOCKCHAIN_INITIATOR_CLIENT ?? "codex",
    responder: process.env.CLOCKCHAIN_RESPONDER_CLIENT ?? "claude",
  };
  const authentication = {
    initiator: await authenticationFor(clients.initiator),
    responder: await authenticationFor(clients.responder),
  };
  const ownsParent = process.env.CLOCKCHAIN_FRESH_AGENT_PARENT === undefined;
  const parent = process.env.CLOCKCHAIN_FRESH_AGENT_PARENT ?? await mkdtemp(join(tmpdir(), "clockchain-fresh-agent-"));
  try {
    const evidence = await runFreshAgentHandshake({
      clients,
      configureClient: (entry) => configureClient({ ...entry, authentication: authentication[entry.role] }),
      prepareClient: (entry) => prepareClient({ ...entry, authentication: authentication[entry.role] }),
      modelEnvironment: {
        initiator: authentication.initiator.environment,
        responder: authentication.responder.environment,
      },
      secretCanaries: {
        initiator: authentication.initiator.secretCanaries,
        responder: authentication.responder.secretCanaries,
      },
      monitor,
      parent,
      prompts: { initiator: prompts.initiator, responder: prompts.responder },
      release: {
        mcp: {
          manifestDigest: value("CLOCKCHAIN_MCP_RELEASE_MANIFEST_DIGEST"),
          hostRoots: roots("CLOCKCHAIN_MCP_HOST_ROOT_FINGERPRINTS"),
        },
        research: {
          manifestDigest: value("CLOCKCHAIN_RESEARCH_RELEASE_MANIFEST_DIGEST"),
          hostRoots: roots("CLOCKCHAIN_RESEARCH_HOST_ROOT_FINGERPRINTS"),
        },
      },
    });
    process.stdout.write(`${JSON.stringify(evidence)}\n`);
  } finally {
    if (ownsParent) await rm(parent, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch(() => {
    process.stderr.write(SAFE_ERROR);
    process.exitCode = 1;
  });
}
