#!/usr/bin/env node

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";

import { createMechanicsProofPartyRuntime } from "../src/testing/mechanics-proof-party-runtime.mjs";

const MCP_ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
const SESSION = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const SECRET_REF = /^arn:aws:(?:secretsmanager|ssm):[a-z0-9-]+:[0-9]{12}:(?:secret|parameter)[:/].+/;
const PRIVATE_DNS = /^(?:[a-z0-9-]+\.)*(?:task\.local|internal|local)$/i;
const MAX_STDIN_BYTES = 256 * 1024;

function value(env, name) {
  const item = env[name];
  if (typeof item !== "string" || item.length === 0) throw new Error("missing");
  return item;
}

function optional(env, name) {
  const item = env[name];
  return typeof item === "string" && item.length > 0 ? item : null;
}

function rejectControllerAuthority(env) {
  for (const [key, item] of Object.entries(env)) {
    if (/(?:SIGNER|PRIVATE_KEY|SIGNER_SEED|A2A_CARD_PRIVATE|ANTHROPIC_API_KEY)/i.test(key) && typeof item === "string" && item.length > 0) {
      throw new Error("authority");
    }
  }
}

function privateA2AEndpoint(raw) {
  let url;
  try { url = new URL(raw); } catch { throw new Error("bad"); }
  const hostname = url.hostname;
  const octets = isIP(hostname) === 4 ? hostname.split(".").map(Number) : [];
  const privateIp =
    octets[0] === 10 ||
    (octets[0] === 192 && octets[1] === 168) ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31);
  if (
    url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.search !== "" ||
    url.hash !== "" || url.pathname !== "/" || url.port !== "8443" ||
    (!privateIp && !PRIVATE_DNS.test(hostname))
  ) throw new Error("bad");
  return raw;
}

function capabilityPreflight(env) {
  rejectControllerAuthority(env);
  const sessionId = value(env, "CLOCKCHAIN_SESSION_ID");
  const role = value(env, "CLOCKCHAIN_ROLE");
  const client = value(env, "CLOCKCHAIN_CLIENT");
  const mcpUrl = value(env, "CLOCKCHAIN_MCP_URL");
  privateA2AEndpoint(value(env, "CLOCKCHAIN_A2A_PEER_ENDPOINT"));
  if (!SESSION.test(sessionId) || !["initiator", "responder"].includes(role) || mcpUrl !== MCP_ENDPOINT) throw new Error("bad");
  if (role === "initiator") {
    if (client !== "codex" || !SECRET_REF.test(value(env, "CLOCKCHAIN_CODEX_AUTH_SECRET_REF"))) throw new Error("bad");
  } else if (
    client !== "claude" || optional(env, "CLOCKCHAIN_CLAUDE_PROVIDER") !== "bedrock" ||
    optional(env, "CLOCKCHAIN_BEDROCK_MODEL_ID") !== "us.anthropic.claude-sonnet-4-6"
  ) throw new Error("bad");
  for (const name of ["CLOCKCHAIN_WORKSPACE", "CLOCKCHAIN_HOME", "CLOCKCHAIN_STATE_DIR"]) value(env, name);
  if (value(env, "CLOCKCHAIN_A2A_PORT") !== "8443") throw new Error("bad");
  const partySigner = privateKeyToAccount(generatePrivateKey());
  const cardSigner = privateKeyToAccount(generatePrivateKey());
  return Object.freeze({
    schema: "clockchain.mechanics-proof-party-capability/v1",
    sessionId,
    role,
    client,
    provider: role === "responder" ? "bedrock" : "codex-bootstrap-ref",
    ...(role === "responder" ? { bedrockModelId: "us.anthropic.claude-sonnet-4-6" } : {}),
    mcpUrl,
    a2aPort: "8443",
    partySignerAddress: partySigner.address.toLowerCase(),
    a2aCardAddress: cardSigner.address.toLowerCase(),
    signerGeneratedInsideRuntime: true,
    a2aCardKeyGeneratedInsideRuntime: true,
    controllerProvidedSignerMaterialAccepted: false,
    providerCredentialValueAccepted: false,
    directA2ARequired: true,
    a2aPeerEndpointScheme: "https-private",
    acpProcessTransportRequired: true,
    agentLoopImplemented: false,
    failClosedUntilLiveDriver: true,
  });
}

function runOptions(env) {
  rejectControllerAuthority(env);
  let mandate;
  try { mandate = JSON.parse(value(env, "CLOCKCHAIN_MANDATE_JSON")); } catch { throw new Error("bad"); }
  const port = Number(value(env, "CLOCKCHAIN_A2A_PORT"));
  const runId = value(env, "CLOCKCHAIN_RUN_ID");
  const role = value(env, "CLOCKCHAIN_ROLE");
  const harness = value(env, "CLOCKCHAIN_CLIENT");
  const manifestDigest = value(env, "CLOCKCHAIN_HELPER_MANIFEST_DIGEST");
  const workloadAttestationDigest = value(env, "CLOCKCHAIN_WORKLOAD_ATTESTATION_DIGEST");
  if (
    !SESSION.test(runId) || !["initiator", "responder"].includes(role) || !["codex", "claude"].includes(harness) ||
    !DIGEST.test(manifestDigest) || !DIGEST.test(workloadAttestationDigest) || port !== 8443
  ) throw new Error("bad");
  return Object.freeze({
    harness,
    listenHost: value(env, "CLOCKCHAIN_A2A_LISTEN_HOST"),
    manifestDigest,
    mandate,
    mcpEndpoint: value(env, "CLOCKCHAIN_MCP_URL"),
    opensslPath: value(env, "CLOCKCHAIN_OPENSSL_PATH"),
    port,
    publicEndpoint: privateA2AEndpoint(value(env, "CLOCKCHAIN_A2A_PUBLIC_ENDPOINT")),
    role,
    root: value(env, "CLOCKCHAIN_PARTY_ROOT"),
    runId,
    runtimeId: value(env, "CLOCKCHAIN_RUNTIME_ID"),
    taskId: value(env, "CLOCKCHAIN_TASK_ID"),
    workloadAttestationDigest,
  });
}

async function oneJsonLine(stdin) {
  let body = "";
  for await (const chunk of stdin) {
    body += Buffer.from(chunk).toString("utf8");
    if (Buffer.byteLength(body) > MAX_STDIN_BYTES) throw new Error("too large");
  }
  const lines = body.split(/\r?\n/).filter((line) => line.length > 0);
  if (lines.length !== 1) throw new Error("lines");
  const parsed = JSON.parse(lines[0]);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("json");
  return parsed;
}

export async function runMain({
  argv = process.argv,
  createRuntime = createMechanicsProofPartyRuntime,
  env = process.env,
  stderr = process.stderr,
  stdin = process.stdin,
  stdout = process.stdout,
} = {}) {
  let runtime = null;
  let runInvoked = false;
  try {
    if (!Array.isArray(argv) || argv.length !== 3) throw new Error("mode");
    if (argv[2] === "--capability-preflight") {
      stdout.write(`${JSON.stringify(capabilityPreflight(env))}\n`);
      return 0;
    }
    if (argv[2] !== "--run") throw new Error("mode");
    runtime = await createRuntime(runOptions(env));
    stdout.write(`${JSON.stringify(runtime.bootstrapDescriptor())}\n`);
    const peerDescriptor = await oneJsonLine(stdin);
    runInvoked = true;
    const evidence = await runtime.run({
      peerDescriptor,
      onPublicEvent(event) { stdout.write(`${JSON.stringify(event)}\n`); },
    });
    stdout.write(`${JSON.stringify(evidence)}\n`);
    return 0;
  } catch {
    if (runtime !== null && !runInvoked) {
      try { await runtime.destroy(); } catch {}
    }
    stderr.write("Mechanics proof party failed safely.\n");
    return 1;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await runMain();
}
