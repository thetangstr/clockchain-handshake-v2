#!/usr/bin/env node

import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { runFreshAgentHandshake } from "../src/testing/fresh-agent-client.mjs";
import { monitorSession } from "../src/testing/fresh-agent-monitor.mjs";

const execFileAsync = promisify(execFile);
const SAFE_ERROR = "Fresh agent compatibility check failed safely.\n";
const SHA256 = /^[0-9a-f]{64}$/;

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

function credentialFor(client) {
  const key = client === "codex" ? "OPENAI_API_KEY" : "ANTHROPIC_API_KEY";
  return { [key]: value(key) };
}

async function configureClient({ command, env }) {
  await execFileAsync(command.file, command.args, {
    env,
    maxBuffer: 64 * 1024,
    timeout: 30_000,
    windowsHide: true,
  });
}

// The monitor URL must be a session-scoped relay template such as
// <base>/v1/sessions/{sessionId}/snapshot. The auth-protected research proxy
// cannot serve anonymous canary polling, and any endpoint that cannot also
// provide the signed result envelope cannot produce a certificateDigest in
// the trusted-proof domain — so non-template URLs fail closed.
function monitor({ sessionId }) {
  return monitorSession({
    endpoint: value("CLOCKCHAIN_RESEARCH_MONITOR_URL"),
    sessionId,
  });
}

async function main() {
  const prompts = JSON.parse(await readFile(new URL("../test/fixtures/fresh-agent/prompts.json", import.meta.url), "utf8"));
  const clients = {
    initiator: process.env.CLOCKCHAIN_INITIATOR_CLIENT ?? "codex",
    responder: process.env.CLOCKCHAIN_RESPONDER_CLIENT ?? "claude",
  };
  const ownsParent = process.env.CLOCKCHAIN_FRESH_AGENT_PARENT === undefined;
  const parent = process.env.CLOCKCHAIN_FRESH_AGENT_PARENT ?? await mkdtemp(join(tmpdir(), "clockchain-fresh-agent-"));
  try {
    const evidence = await runFreshAgentHandshake({
      clients,
      configureClient,
      modelEnvironment: {
        initiator: credentialFor(clients.initiator),
        responder: credentialFor(clients.responder),
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

main().catch(() => {
  process.stderr.write(SAFE_ERROR);
  process.exitCode = 1;
});
