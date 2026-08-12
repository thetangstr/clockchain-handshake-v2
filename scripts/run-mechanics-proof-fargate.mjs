#!/usr/bin/env node

import { fileURLToPath } from "node:url";
import { chmod, lstat, mkdir, open, realpath, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { tmpdir } from "node:os";

import { createAwsCliControlPlane } from "../src/runtime/aws-cli-control-plane.mjs";
import { buildFargateLiveStackPlan } from "../src/runtime/aws-fargate-live-plan.mjs";
import {
  buildFargateLivePreflightPlan,
  buildFargateDryRunSummary,
  loadFargateDryRunPlan,
} from "../src/runtime/aws-fargate-runtime-adapter.mjs";
import { runFargateLiveMechanicsProof } from "../src/runtime/aws-fargate-live-adapter.mjs";

const PRODUCTION_MCP_URL = "https://mcp.clockchain.network/handshake/mcp";
const REQUIRED_TOOLS = Object.freeze([
  "agent_handshake_accept_invitation",
  "agent_handshake_get_certificate",
  "agent_handshake_invite",
  "agent_handshake_join",
  "agent_handshake_next",
  "agent_handshake_status",
  "agent_handshake_submit",
  "agent_handshake_submit_checkpoint",
].sort());

function fail() {
  throw new Error("Fargate mechanics proof runner failed safely.");
}

function die() {
  process.stderr.write("Fargate mechanics proof runner failed safely.\n");
  process.exitCode = 1;
}

function take(args, flag) {
  const index = args.indexOf(flag);
  if (index < 0 || index === args.length - 1) fail();
  const value = args[index + 1];
  args.splice(index, 2);
  return value;
}

function number(value, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > max) fail();
  return parsed;
}

export function parseFargateRunnerArgs(argv = process.argv) {
  const args = argv.slice(2);
  if (args.length === 1 && args[0] === "--dry-run") return Object.freeze({ mode: "dry-run" });
  if (args.includes("--dry-run") && args.includes("--run")) fail();
  if (
    args.length === 8 &&
    args[0] === "--preflight" &&
    args[1] === "--pair" &&
    args[3] === "--direct-a2a" &&
    args[4] === "--evidence-dir" &&
    args[6] === "--app-image"
  ) {
    return Object.freeze({ mode: "preflight", pair: args[2], evidenceDir: args[5], appImage: args[7] });
  }
  const mode = args.shift();
  if (mode !== "--run") fail();
  const parsed = {
    mode: "run",
    accountId: take(args, "--account"),
    region: take(args, "--region"),
    runId: take(args, "--run-id"),
    vpcId: take(args, "--vpc-id"),
    publicSubnetId: take(args, "--public-subnet-id"),
    initiatorPrivateSubnet: { cidr: take(args, "--initiator-private-cidr"), availabilityZone: take(args, "--initiator-az") },
    responderPrivateSubnet: { cidr: take(args, "--responder-private-cidr"), availabilityZone: take(args, "--responder-az") },
    codexSecretArn: take(args, "--codex-secret-arn"),
    appImage: take(args, "--image"),
    evidenceDir: take(args, "--evidence-dir"),
    ttlSeconds: number(take(args, "--ttl-seconds"), 3600),
    budgetUsd: number(take(args, "--budget-usd"), 25),
    mcpUrl: take(args, "--mcp-url"),
    maxConcurrency: 2,
  };
  if (args.length !== 0 || parsed.mcpUrl !== PRODUCTION_MCP_URL) fail();
  parsed.bedrockModelArn = `arn:aws:bedrock:${parsed.region}:${parsed.accountId}:inference-profile/us.anthropic.claude-sonnet-4-6`;
  return Object.freeze(parsed);
}

function parseMcpEnvelope(bytes, contentType) {
  if (typeof bytes !== "string" || bytes.length === 0 || bytes.length > 131_072) fail();
  if (/event-stream/i.test(contentType)) {
    const messages = bytes.trim().split(/\n\n+/).filter(Boolean);
    if (messages.length !== 1) fail();
    const lines = messages[0].split(/\n/);
    if (lines[0] !== "event: message") fail();
    const data = lines.find((line) => line.startsWith("data: "));
    if (!data) fail();
    return JSON.parse(data.slice(6));
  }
  return JSON.parse(bytes);
}

async function rpc(fetchImpl, url, method) {
  const id = `clockchain-fargate-${method}`;
  const response = await fetchImpl(url, {
    method: "POST",
    redirect: "error",
    headers: Object.freeze({ "content-type": "application/json", accept: "application/json, text/event-stream" }),
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params: method === "initialize" ? { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "clockchain-fargate-controller", version: "2.1.2" } } : {} }),
    signal: AbortSignal.timeout(5000),
  });
  if (response?.ok !== true) fail();
  const contentType = response.headers?.get?.("content-type") ?? "";
  const contentLength = response.headers?.get?.("content-length");
  if (contentLength !== null && contentLength !== undefined && Number(contentLength) > 131_072) fail();
  try {
    const envelope = parseMcpEnvelope(await response.text(), contentType);
    if (envelope.id !== id) fail();
    return envelope;
  } catch {
    fail();
  }
}

export async function checkProductionMcpGate(options = {}) {
  const url = options.url ?? options.mcpUrl;
  if (url !== PRODUCTION_MCP_URL) fail();
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") fail();
  let health;
  try {
    health = await fetchImpl("https://mcp.clockchain.network/health", {
      method: "GET",
      redirect: "error",
      headers: Object.freeze({ accept: "application/json" }),
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    fail();
  }
  if (health?.ok !== true) fail();
  const healthLength = health.headers?.get?.("content-length");
  if (healthLength !== null && healthLength !== undefined && Number(healthLength) > 131_072) fail();
  let healthBody;
  try {
    healthBody = JSON.parse(await health.text());
  } catch {
    fail();
  }
  if (JSON.stringify(healthBody) !== JSON.stringify({ status: "ok" })) fail();
  const initialize = await rpc(fetchImpl, url, "initialize");
  const initResult = initialize.result;
  if (
    initialize.jsonrpc !== "2.0" ||
    initResult?.serverInfo?.name !== "clockchain-agent-handshake" ||
    initResult.serverInfo.version !== "2.1.2" ||
    initResult.protocolVersion !== "2025-06-18"
  ) fail();
  const toolsEnvelope = await rpc(fetchImpl, url, "tools/list");
  const result = toolsEnvelope.result;
  if (toolsEnvelope.jsonrpc !== "2.0" || !Array.isArray(result?.tools)) fail();
  const names = result.tools.map((tool) => tool?.name).sort();
  if (new Set(names).size !== names.length) fail();
  if (JSON.stringify(names) !== JSON.stringify(REQUIRED_TOOLS)) fail();
  return Object.freeze({ healthy: true, checkpointTool: true, endpoint: url, toolNames: Object.freeze(names) });
}

async function retainEvidenceFile(evidenceDir, evidence) {
  const handle = await open(join(evidenceDir, "controller-evidence.json"), "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(evidence)}\n`, "utf8");
  } finally {
    await handle.close();
  }
}

export async function retainFargateSuccessEvidence(evidenceDir, evidence) {
  try {
    await reserveFargateEvidenceDir(evidenceDir);
    await retainEvidenceFile(evidenceDir, evidence);
    await chmod(join(evidenceDir, "controller-evidence.json"), 0o600);
    if (((await stat(join(evidenceDir, "controller-evidence.json"))).mode & 0o777) !== 0o600) fail();
  } catch (error) {
    if (error?.message === "Fargate mechanics proof runner failed safely.") throw error;
    fail();
  }
}

export async function reserveFargateEvidenceDir(evidenceDir) {
  const allowedRoots = [tmpdir(), "/private/tmp", resolve(process.cwd(), ".tmp")];
  if (
    typeof evidenceDir !== "string" ||
    !isAbsolute(evidenceDir) ||
    resolve(evidenceDir) !== evidenceDir ||
    evidenceDir === "/" ||
    evidenceDir === process.env.HOME ||
    !/^mechanics-proof/.test(basename(evidenceDir)) ||
    !allowedRoots.some((root) => evidenceDir === root || evidenceDir.startsWith(`${root}/`)) ||
    dirname(evidenceDir) === "/etc"
  ) fail();
  try {
    const existing = await lstat(evidenceDir).catch((error) => {
      if (error?.code === "ENOENT") return null;
      throw error;
    });
    if (existing?.isSymbolicLink()) fail();
    if (existing) {
      if (!existing.isDirectory() || (existing.mode & 0o777) !== 0o700) fail();
    } else {
      await mkdir(evidenceDir, { recursive: false, mode: 0o700 });
      await chmod(evidenceDir, 0o700);
    }
    const realParent = await realpath(dirname(evidenceDir));
    const realAllowed = await Promise.all(allowedRoots.map((root) => realpath(root).catch(() => root)));
    if (!realAllowed.some((root) => realParent === root || realParent.startsWith(`${root}/`))) fail();
    await realpath(evidenceDir);
  } catch (error) {
    if (error?.message === "Fargate mechanics proof runner failed safely.") throw error;
    fail();
  }
}

async function main() {
  try {
    const parsed = parseFargateRunnerArgs(process.argv);
    if (parsed.mode === "dry-run") {
      const plan = await loadFargateDryRunPlan();
      process.stdout.write(`${JSON.stringify(buildFargateDryRunSummary(plan))}\n`);
      return;
    }
    if (parsed.mode === "preflight") {
      const plan = await loadFargateDryRunPlan();
      const summary = await buildFargateLivePreflightPlan({
        plan,
        pair: parsed.pair,
        directA2A: true,
        mcpUrl: PRODUCTION_MCP_URL,
        evidenceDir: parsed.evidenceDir,
        appImage: parsed.appImage,
      });
      process.stdout.write(`${JSON.stringify(summary)}\n`);
      return;
    }
    await reserveFargateEvidenceDir(parsed.evidenceDir);
    const controlPlane = createAwsCliControlPlane({ region: parsed.region });
    const startedAt = new Date().toISOString();
    const expiresAt = new Date(Date.parse(startedAt) + parsed.ttlSeconds * 1000).toISOString();
    const networkInspection = await controlPlane.inspectNetwork({
      vpcId: parsed.vpcId,
      publicSubnetId: parsed.publicSubnetId,
      initiatorPrivateCidr: parsed.initiatorPrivateSubnet.cidr,
      responderPrivateCidr: parsed.responderPrivateSubnet.cidr,
    });
    const plan = await buildFargateLiveStackPlan({
      accountId: parsed.accountId,
      appImage: parsed.appImage,
      bedrockModelArn: parsed.bedrockModelArn,
      budgetUsd: parsed.budgetUsd,
      codexSecretArn: parsed.codexSecretArn,
      expiresAt,
      initiatorPrivateSubnet: parsed.initiatorPrivateSubnet,
      maxConcurrency: 2,
      mcpUrl: parsed.mcpUrl,
      networkInspection,
      publicSubnetId: parsed.publicSubnetId,
      region: parsed.region,
      responderPrivateSubnet: parsed.responderPrivateSubnet,
      runId: parsed.runId,
      startedAt,
      ttlSeconds: parsed.ttlSeconds,
      vpcId: parsed.vpcId,
    });
    const result = await runFargateLiveMechanicsProof({
      plan,
      controlPlane,
      mcpGate: checkProductionMcpGate,
      retainEvidence: (evidence) => retainFargateSuccessEvidence(parsed.evidenceDir, evidence),
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (result.status !== "SUCCEEDED") process.exitCode = 1;
  } catch {
    die();
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await main();
}
