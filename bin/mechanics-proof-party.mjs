#!/usr/bin/env node

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";

import { createStdinBootstrapExchange } from "../src/runtime/stdin-bootstrap-exchange.mjs";
import { createTaskRoleAwsSqsBootstrapExchange } from "../src/runtime/aws-sqs-bootstrap-exchange.mjs";
import { resolveAwsEcsTaskBootstrap } from "../src/runtime/aws-ecs-task-bootstrap.mjs";
import {
  createMechanicsProofPartyRuntime,
  mechanicsProofPartyRuntimeFailureStage,
} from "../src/testing/mechanics-proof-party-runtime.mjs";

const MCP_ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
const SESSION = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const SECRET_REF = /^arn:aws:(?:secretsmanager|ssm):[a-z0-9-]+:[0-9]{12}:(?:secret|parameter)[:/].+/;
const CODEX_AUTH_BASE64 = /^[A-Za-z0-9+/=]{4,98304}$/;
const CLAUDE_AUTH_BASE64 = CODEX_AUTH_BASE64;
const PRIVATE_DNS = /^(?:[a-z0-9-]+\.)*(?:task\.local|internal|local)$/i;
const MANAGED_IDLE_MS = 300_000;

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

function rejectCrossRoleProviderAuth(env, role) {
  const codexKeys = ["CLOCKCHAIN_CODEX_AUTH_SECRET_REF", "CLOCKCHAIN_CODEX_AUTH_JSON_BASE64", "CODEX_API_KEY", "OPENAI_API_KEY", "CLOCKCHAIN_CODEX_MODEL"];
  const claudeKeys = [
    "CLOCKCHAIN_CLAUDE_PROVIDER", "CLOCKCHAIN_BEDROCK_MODEL_ID", "CLOCKCHAIN_CLAUDE_AUTH_JSON_BASE64", "CLOCKCHAIN_CLAUDE_MODEL", "CLAUDE_CODE_USE_BEDROCK", "ANTHROPIC_MODEL",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN",
  ];
  const forbidden = role === "initiator" ? claudeKeys : codexKeys;
  for (const key of forbidden) if (optional(env, key) !== null) throw new Error("cross-role");
}

function codexAuthMode(env) {
  const modes = [];
  const secretRef = optional(env, "CLOCKCHAIN_CODEX_AUTH_SECRET_REF");
  const serialized = optional(env, "CLOCKCHAIN_CODEX_AUTH_JSON_BASE64");
  const codexApiKey = optional(env, "CODEX_API_KEY");
  const openaiApiKey = optional(env, "OPENAI_API_KEY");
  if (secretRef !== null) {
    if (!SECRET_REF.test(secretRef)) throw new Error("bad");
    modes.push("codex-bootstrap-ref");
  }
  if (serialized !== null) {
    if (!CODEX_AUTH_BASE64.test(serialized)) throw new Error("bad");
    modes.push("codex-subscription-auth");
  }
  if (codexApiKey !== null) modes.push("codex-api-key");
  if (openaiApiKey !== null) modes.push("openai-api-key");
  if (modes.length !== 1) throw new Error("bad");
  if (modes[0] !== "codex-bootstrap-ref" && optional(env, "CLOCKCHAIN_CODEX_MODEL") !== "gpt-5.6-terra") throw new Error("bad");
  return modes[0];
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
  rejectCrossRoleProviderAuth(env, role);
  let provider;
  if (role === "initiator") {
    if (client !== "codex") throw new Error("bad");
    provider = codexAuthMode(env);
  } else {
    if (client !== "claude") throw new Error("bad");
    const serialized = optional(env, "CLOCKCHAIN_CLAUDE_AUTH_JSON_BASE64");
    const bedrock = optional(env, "CLOCKCHAIN_CLAUDE_PROVIDER") === "bedrock" &&
      optional(env, "CLOCKCHAIN_BEDROCK_MODEL_ID") === "us.anthropic.claude-sonnet-4-6";
    if ((serialized !== null) === bedrock) throw new Error("bad");
    if (serialized !== null) {
      if (!CLAUDE_AUTH_BASE64.test(serialized) || optional(env, "CLOCKCHAIN_CLAUDE_MODEL") !== "sonnet") throw new Error("bad");
      provider = "claude-subscription-auth";
    } else provider = "bedrock";
  }
  for (const name of ["CLOCKCHAIN_WORKSPACE", "CLOCKCHAIN_HOME", "CLOCKCHAIN_STATE_DIR"]) value(env, name);
  if (value(env, "CLOCKCHAIN_A2A_PORT") !== "8443") throw new Error("bad");
  const partySigner = privateKeyToAccount(generatePrivateKey());
  const cardSigner = privateKeyToAccount(generatePrivateKey());
  return Object.freeze({
    schema: "clockchain.mechanics-proof-party-capability/v1",
    sessionId,
    role,
    client,
    provider,
    ...(role === "responder" ? provider === "bedrock"
      ? { bedrockModelId: "us.anthropic.claude-sonnet-4-6" }
      : { modelId: "sonnet" } : {}),
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
    agentLoopImplemented: true,
    failClosedUntilLiveDriver: false,
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

function managedExchangeEnvironment(env) {
  for (const key of [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_PROFILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_SQS",
  ]) if (optional(env, key) !== null) throw new Error("aws-auth-override");
  return Object.freeze({
    ownQueueUrl: value(env, "CLOCKCHAIN_BOOTSTRAP_OWN_QUEUE_URL"),
    peerQueueUrl: value(env, "CLOCKCHAIN_BOOTSTRAP_PEER_QUEUE_URL"),
    region: value(env, "AWS_REGION"),
  });
}

function waitForManagedStop({ timeoutMs = MANAGED_IDLE_MS, signalSource = process } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    let timer;
    const done = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signalSource.off?.("SIGTERM", done);
      signalSource.off?.("SIGINT", done);
      resolve();
    };
    timer = setTimeout(done, timeoutMs);
    signalSource.once?.("SIGTERM", done);
    signalSource.once?.("SIGINT", done);
  });
}

export async function runMain({
  argv = process.argv,
  createBootstrapExchange = createStdinBootstrapExchange,
  createManagedBootstrapExchange = createTaskRoleAwsSqsBootstrapExchange,
  createRuntime = createMechanicsProofPartyRuntime,
  env = process.env,
  stderr = process.stderr,
  stdin = process.stdin,
  stdout = process.stdout,
  resolveManagedRunOptions = resolveAwsEcsTaskBootstrap,
  holdManagedRun = argv === process.argv ? waitForManagedStop : async () => {},
} = {}) {
  let bootstrapExchange = null;
  let bootstrapExchangeDestroyed = false;
  let runtime = null;
  let runInvoked = false;
  let failureStage = null;
  try {
    if (!Array.isArray(argv) || argv.length !== 3) throw new Error("mode");
    if (argv[2] === "--capability-preflight") {
      stdout.write(`${JSON.stringify(capabilityPreflight(env))}\n`);
      return 0;
    }
    if (!["--run", "--run-managed"].includes(argv[2])) throw new Error("mode");
    const managedEnvironment = argv[2] === "--run-managed" ? managedExchangeEnvironment(env) : null;
    const resolved = argv[2] === "--run-managed" ? await resolveManagedRunOptions({ env }) : { runOptions: runOptions(env) };
    const options = resolved?.runOptions ?? resolved;
    if (resolved?.attestation !== undefined) {
      stdout.write(`${JSON.stringify(resolved.attestation)}\n`);
    }
    failureStage = "runtime-create";
    runtime = await createRuntime(options);
    failureStage = "exchange-create";
    bootstrapExchange = argv[2] === "--run-managed"
      ? createManagedBootstrapExchange(Object.freeze({ ...managedEnvironment, role: options.role, runId: options.runId }))
      : createBootstrapExchange({ role: options.role, runId: options.runId, stdin, stdout });
    failureStage = "bootstrap-publish";
    await bootstrapExchange.publishOwnDescriptor(runtime.bootstrapDescriptor());
    failureStage = "bootstrap-await";
    const peerDescriptor = await bootstrapExchange.awaitPeerDescriptor();
    failureStage = "exchange-destroy";
    await bootstrapExchange.destroy();
    bootstrapExchangeDestroyed = true;
    runInvoked = true;
    failureStage = "runtime-run";
    const evidence = await runtime.run({
      peerDescriptor,
      onPublicEvent(event) { stdout.write(`${JSON.stringify(event)}\n`); },
    });
    stdout.write(`${JSON.stringify(evidence)}\n`);
    if (argv[2] === "--run-managed") {
      failureStage = "managed-hold";
      await holdManagedRun();
    }
    return 0;
  } catch (error) {
    const runtimeSubstage = failureStage === "runtime-run" ? mechanicsProofPartyRuntimeFailureStage(error) : null;
    if (bootstrapExchange !== null && !bootstrapExchangeDestroyed) {
      try { await bootstrapExchange.destroy(); } catch {}
    }
    if (runtime !== null && !runInvoked) {
      try { await runtime.destroy(); } catch {}
    }
    const reportedStage = runtimeSubstage === null ? failureStage : `${failureStage}.${runtimeSubstage}`;
    stderr.write(`Mechanics proof party failed safely.${reportedStage === null ? "" : ` stage=${reportedStage}`}\n`);
    return 1;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await runMain();
}
