#!/usr/bin/env node

import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  FreshAgentDiagnosticError,
  assertFreshAgentNodeRuntime,
  runFreshAgentHandshake,
  validateClaudePreparation,
  validateFreshAgentMonitorSnapshot,
  writeFreshAgentAttemptArtifact,
} from "../src/testing/fresh-agent-client.mjs";
import {
  installAppleClientAuthentication,
  loadAppleClientAuthentication,
} from "../src/testing/apple-client-auth.mjs";

const execFileAsync = promisify(execFile);
const SAFE_ERROR = "Fresh agent compatibility check failed safely.\n";
const SHA256 = /^[0-9a-f]{64}$/;
const TRANSIENT_MONITOR_STATUSES = new Set([429, 500, 502, 503, 504]);

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

async function probeClaudeExistingLogin() {
  try {
    const { stdout } = await execFileAsync("claude", ["auth", "status"], {
      env: process.env,
      maxBuffer: 64 * 1024,
      timeout: 30_000,
      windowsHide: true,
    });
    const status = JSON.parse(stdout);
    return status?.loggedIn === true && status?.authMethod === "claude.ai";
  } catch {
    return false;
  }
}

export async function loadFreshAgentAuthentication(client, {
  env = process.env,
  home = homedir(),
  existingLoginProbe = probeClaudeExistingLogin,
} = {}) {
  const key = client === "codex" ? "OPENAI_API_KEY" : "ANTHROPIC_API_KEY";
  const credential = env[key];
  const oauthToken = client === "claude" ? env.CLAUDE_CODE_OAUTH_TOKEN : undefined;
  const supplied = [credential, oauthToken].filter((entry) => typeof entry === "string" && entry.length > 0);
  if (supplied.length > 1) throw new Error("invalid");
  const existingLoginIsolated = client === "claude" && env.CLOCKCHAIN_CLAUDE_EXISTING_LOGIN === "1";
  if (existingLoginIsolated) {
    if (supplied.length !== 0 || typeof existingLoginProbe !== "function" || await existingLoginProbe() !== true) throw new Error("invalid");
    return Object.freeze({
      client,
      environment: Object.freeze({}),
      existingLoginIsolated: true,
      secretCanaries: Object.freeze([]),
      serialized: null,
      source: null,
    });
  }
  if (supplied.length === 1) {
    const environmentKey = typeof credential === "string" && credential.length > 0
      ? key
      : "CLAUDE_CODE_OAUTH_TOKEN";
    return Object.freeze({
      client,
      environment: Object.freeze({ [environmentKey]: supplied[0] }),
      secretCanaries: Object.freeze([supplied[0]]),
      serialized: null,
      source: null,
    });
  }
  const override = client === "codex" ? "CLOCKCHAIN_CODEX_AUTH_FILE" : "CLOCKCHAIN_CLAUDE_AUTH_FILE";
  const source = env[override] ?? join(home, client === "codex" ? ".codex/auth.json" : ".claude/.credentials.json");
  return loadAppleClientAuthentication({ client, nowMs: Date.now(), source });
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
  const endpointTemplate = value("CLOCKCHAIN_RESEARCH_MONITOR_URL");
  const exactSessionEndpoint = endpointTemplate.includes("{sessionId}");
  const endpoint = endpointTemplate.replace("{sessionId}", encodeURIComponent(sessionId));
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
      if (!TRANSIENT_MONITOR_STATUSES.has(status) && !(status === 404 && exactSessionEndpoint)) {
        throw safeMonitorError("http", `HTTP_${status}`);
      }
      await new Promise((resolvePromise) => setTimeout(resolvePromise, Math.min(retryDelayMs, Math.max(0, deadline - Date.now()))));
      continue;
    }
    const completed = validateFreshAgentMonitorSnapshot(await response.json(), sessionId);
    if (completed !== null) return completed;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, Math.min(retryDelayMs, Math.max(0, deadline - Date.now()))));
  }
  throw safeMonitorError("deadline", "TIMEOUT");
}

export async function runFreshAgentCliAttempt({
  artifactDirectory,
  attemptId = randomUUID(),
  preflight = async () => ({}),
  runHandshake,
  secretCanaries = [],
  writeArtifact = writeFreshAgentAttemptArtifact,
  writeOutput = (value) => process.stdout.write(value),
} = {}) {
  if (typeof preflight !== "function" || typeof runHandshake !== "function" || typeof writeArtifact !== "function" || typeof writeOutput !== "function") throw new Error("invalid");
  let outcome;
  let preflightResult = {};
  try {
    preflightResult = await preflight();
    outcome = Object.freeze({ outcome: "success", evidence: await runHandshake(preflightResult) });
  } catch (error) {
    outcome = Object.freeze({ outcome: "failure", error });
  }
  const artifactCanaries = [
    ...secretCanaries,
    ...(Array.isArray(preflightResult?.secretCanaries) ? preflightResult.secretCanaries : []),
  ];
  await writeArtifact(outcome.outcome === "success"
    ? {
        attemptId,
        directory: artifactDirectory,
        evidence: outcome.evidence,
        outcome: outcome.outcome,
        secretCanaries: artifactCanaries,
      }
    : {
        attemptId,
        directory: artifactDirectory,
        error: outcome.error,
        outcome: outcome.outcome,
        secretCanaries: artifactCanaries,
      });
  if (outcome.outcome === "failure") throw outcome.error;
  writeOutput(`${JSON.stringify(outcome.evidence)}\n`);
  return outcome.evidence;
}

async function main() {
  const artifactDirectory = value("CLOCKCHAIN_FRESH_AGENT_RESULT_DIR");
  const ownsParent = process.env.CLOCKCHAIN_FRESH_AGENT_PARENT === undefined;
  const parent = process.env.CLOCKCHAIN_FRESH_AGENT_PARENT ?? await mkdtemp(join(tmpdir(), "clockchain-fresh-agent-"));
  try {
    const prompts = JSON.parse(await readFile(new URL("../test/fixtures/fresh-agent/prompts.json", import.meta.url), "utf8"));
    for (const role of ["initiator", "responder"]) {
      prompts[role] = `${prompts[role]}\n\n${prompts.actionDecision}`;
    }
    delete prompts.actionDecision;
    const clients = {
      initiator: process.env.CLOCKCHAIN_INITIATOR_CLIENT ?? "codex",
      responder: process.env.CLOCKCHAIN_RESPONDER_CLIENT ?? "claude",
    };
    await runFreshAgentCliAttempt({
      artifactDirectory,
      preflight: async () => {
        const runtime = assertFreshAgentNodeRuntime();
        let authentication;
        try {
          authentication = {
            initiator: await loadFreshAgentAuthentication(clients.initiator),
            responder: await loadFreshAgentAuthentication(clients.responder),
          };
        } catch {
          throw new FreshAgentDiagnosticError({ phase: "preflight", category: "authentication", code: "AUTHENTICATION_FAILED" });
        }
        return Object.freeze({
          authentication,
          runtime,
          secretCanaries: [
            ...authentication.initiator.secretCanaries,
            ...authentication.responder.secretCanaries,
            parent,
          ],
        });
      },
      runHandshake: ({ authentication, runtime }) => runFreshAgentHandshake({
        authenticationModes: {
          initiator: authentication.initiator.existingLoginIsolated === true ? "existing_login_isolated" : "disposable",
          responder: authentication.responder.existingLoginIsolated === true ? "existing_login_isolated" : "disposable",
        },
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
        runtimeExecPath: runtime.execPath,
        runtimeVersion: runtime.version,
      }),
    });
  } catch (error) {
    process.stderr.write(SAFE_ERROR);
    process.exitCode = 1;
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
