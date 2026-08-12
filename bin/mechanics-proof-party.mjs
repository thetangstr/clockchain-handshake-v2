#!/usr/bin/env node

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { isIP } from "node:net";

const MCP_ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
const SESSION = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SECRET_REF = /^arn:aws:(?:secretsmanager|ssm):[a-z0-9-]+:[0-9]{12}:(?:secret|parameter)[:/].+/;
const PRIVATE_DNS = /^(?:[a-z0-9-]+\.)*(?:task\.local|internal|local)$/i;

function fail() {
  process.stderr.write("Mechanics proof party failed safely.\n");
  process.exitCode = 1;
}

function value(name) {
  const item = process.env[name];
  if (typeof item !== "string" || item.length === 0) throw new Error("missing");
  return item;
}

function optional(name) {
  const item = process.env[name];
  return typeof item === "string" && item.length > 0 ? item : null;
}

function rejectControllerAuthority() {
  for (const [key, value] of Object.entries(process.env)) {
    if (/(?:SIGNER|PRIVATE_KEY|SIGNER_SEED|A2A_CARD_PRIVATE|ANTHROPIC_API_KEY)/i.test(key) && typeof value === "string" && value.length > 0) {
      throw new Error("authority");
    }
  }
}

function publicDigestAddress(account) {
  return account.address.toLowerCase();
}

function privateA2AEndpoint(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("bad");
  }
  const hostname = url.hostname;
  const octets = isIP(hostname) === 4 ? hostname.split(".").map(Number) : [];
  const privateIp =
    octets[0] === 10 ||
    (octets[0] === 192 && octets[1] === 168) ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31);
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.pathname !== "/" ||
    url.port !== "8443" ||
    (!privateIp && !PRIVATE_DNS.test(hostname))
  ) throw new Error("bad");
  return raw;
}

function capabilityPreflight() {
  rejectControllerAuthority();
  const sessionId = value("CLOCKCHAIN_SESSION_ID");
  const role = value("CLOCKCHAIN_ROLE");
  const client = value("CLOCKCHAIN_CLIENT");
  const mcpUrl = value("CLOCKCHAIN_MCP_URL");
  const a2aPeerEndpoint = privateA2AEndpoint(value("CLOCKCHAIN_A2A_PEER_ENDPOINT"));
  if (!SESSION.test(sessionId) || !["initiator", "responder"].includes(role) || mcpUrl !== MCP_ENDPOINT) throw new Error("bad");
  if (role === "initiator") {
    if (client !== "codex" || !SECRET_REF.test(value("CLOCKCHAIN_CODEX_AUTH_SECRET_REF"))) throw new Error("bad");
  } else if (client !== "claude" || optional("CLOCKCHAIN_CLAUDE_PROVIDER") !== "bedrock" || optional("CLOCKCHAIN_BEDROCK_MODEL_ID") !== "us.anthropic.claude-sonnet-4-6") {
    throw new Error("bad");
  }
  for (const name of ["CLOCKCHAIN_WORKSPACE", "CLOCKCHAIN_HOME", "CLOCKCHAIN_STATE_DIR"]) value(name);
  if (value("CLOCKCHAIN_A2A_PORT") !== "8443") throw new Error("bad");
  const partySigner = privateKeyToAccount(generatePrivateKey());
  const cardSigner = privateKeyToAccount(generatePrivateKey());
  const result = {
    schema: "clockchain.mechanics-proof-party-capability/v1",
    sessionId,
    role,
    client,
    provider: role === "responder" ? "bedrock" : "codex-bootstrap-ref",
    ...(role === "responder" ? { bedrockModelId: "us.anthropic.claude-sonnet-4-6" } : {}),
    mcpUrl,
    a2aPort: "8443",
    partySignerAddress: publicDigestAddress(partySigner),
    a2aCardAddress: publicDigestAddress(cardSigner),
    signerGeneratedInsideRuntime: true,
    a2aCardKeyGeneratedInsideRuntime: true,
    controllerProvidedSignerMaterialAccepted: false,
    providerCredentialValueAccepted: false,
    directA2ARequired: true,
    a2aPeerEndpointScheme: "https-private",
    acpProcessTransportRequired: true,
    agentLoopImplemented: false,
    failClosedUntilLiveDriver: true,
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

try {
  if (process.argv.length !== 3 || process.argv[2] !== "--capability-preflight") throw new Error("mode");
  capabilityPreflight();
} catch {
  fail();
}
