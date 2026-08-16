import { randomUUID } from "node:crypto";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

import { getAddress, keccak256, toBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { assertSecretFree } from "../core/redact.mjs";
import { readPrivateText } from "../core/private-path.mjs";

const ROLES = Object.freeze(["buyer", "provider"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^0x[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const INTEGER = /^(?:0|[1-9][0-9]*)$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1", "localhost"]);

export const AGENT_CONTRACT_A2A_TOOLS = Object.freeze([
  Object.freeze({
    name: "agent_contract_discover_counterparty",
    title: "Discover the counterparty Agent Card",
    description: "Read the authenticated Agent Card for the other party in this facilitated session.",
    inputSchema: Object.freeze({ type: "object", additionalProperties: false, properties: {} }),
  }),
  Object.freeze({
    name: "agent_contract_send_proposal",
    title: "Send a firm service proposal",
    description: "Provider only. Sign and send one typed proposal using the existing verified agent wallet.",
    inputSchema: Object.freeze({
      type: "object",
      additionalProperties: false,
      properties: Object.freeze({
        deliverableSummary: Object.freeze({ type: "string", minLength: 1 }),
        formats: Object.freeze({
          type: "array",
          minItems: 1,
          maxItems: 2,
          uniqueItems: true,
          items: Object.freeze({ type: "string", enum: Object.freeze(["json", "markdown"]) }),
        }),
        deliveryHours: Object.freeze({ type: "integer", minimum: 1, maximum: 24 }),
        price: Object.freeze({ type: "string", pattern: "^(?:0|[1-9]|1[0-9]|20)$" }),
        verificationMethod: Object.freeze({ type: "string", const: "checksum-and-required-sections/v1" }),
      }),
      required: Object.freeze(["deliverableSummary", "formats", "deliveryHours", "price", "verificationMethod"]),
    }),
  }),
  Object.freeze({
    name: "agent_contract_read_inbox",
    title: "Read the authenticated session inbox",
    description: "Read messages that Agent Contract has stored for this role.",
    inputSchema: Object.freeze({ type: "object", additionalProperties: false, properties: {} }),
  }),
  Object.freeze({
    name: "agent_contract_acknowledge_proposal",
    title: "Acknowledge a stored proposal",
    description: "Buyer only. Sign a nonbinding received-for-review acknowledgment for an exact stored proposal.",
    inputSchema: Object.freeze({
      type: "object",
      additionalProperties: false,
      properties: Object.freeze({
        taskId: Object.freeze({ type: "string", format: "uuid" }),
        decision: Object.freeze({ type: "string", const: "received_for_review" }),
      }),
      required: Object.freeze(["taskId", "decision"]),
    }),
  }),
]);

function fail(message) {
  throw new TypeError(message);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactObject(value, keys, label) {
  if (!isPlainObject(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    fail(`${label} has invalid fields.`);
  }
  return value;
}

function normalizeCanonical(value, path = "$") {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) fail(`Unsupported canonical number at ${path}.`);
    return value;
  }
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length) fail(`Unsupported canonical array at ${path}.`);
    return value.map((entry, index) => normalizeCanonical(entry, `${path}[${index}]`));
  }
  if (!isPlainObject(value)) fail(`Unsupported canonical value at ${path}.`);
  if (Object.getOwnPropertySymbols(value).length > 0) fail(`Unsupported canonical object at ${path}.`);
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, normalizeCanonical(value[key], `${path}.${key}`)]));
}

export function canonicalJson(value) {
  return JSON.stringify(normalizeCanonical(value));
}

export function canonicalDigest(value) {
  return keccak256(toBytes(canonicalJson(value)));
}

function loopbackBaseUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail("Agent Contract base URL must be a loopback URL.");
  }
  if (
    parsed.protocol !== "http:" || !LOOPBACK_HOSTS.has(parsed.hostname) ||
    parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "" ||
    !["", "/"].includes(parsed.pathname)
  ) {
    fail("Agent Contract base URL must be a plain loopback HTTP origin.");
  }
  return parsed.origin;
}

function strictIso(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    fail("Agent Contract timestamp must be strict ISO time.");
  }
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) fail("Agent Contract timestamp is invalid.");
  return value;
}

function publicJson(value, canaries) {
  assertSecretFree(value, canaries);
  return value;
}

function validateConfig(input) {
  if (!isPlainObject(input) || !ROLES.includes(input.role)) fail("Agent Contract adapter role is invalid.");
  for (const key of ["sessionId", "certificateDigest", "continuationDigest", "address", "erc8004AgentId", "partyId", "opportunityId", "roleCapability", "walletPath"]) {
    if (typeof input[key] !== "string" || input[key].length === 0) fail(`Agent Contract adapter ${key} is required.`);
  }
  if (!UUID.test(input.sessionId) || !DIGEST.test(input.certificateDigest) ||
    !DIGEST.test(input.continuationDigest) || !ADDRESS.test(input.address) ||
    !INTEGER.test(input.erc8004AgentId)) {
    fail("Agent Contract adapter trust binding is invalid.");
  }
  if (typeof input.fetchImpl !== "function" || typeof input.now !== "function") fail("Agent Contract adapter dependencies are invalid.");
  return Object.freeze({ ...input, baseUrl: loopbackBaseUrl(input.baseUrl), address: getAddress(input.address) });
}

async function readWallet(config) {
  let wallet;
  try {
    wallet = JSON.parse(await readPrivateText({ path: config.walletPath, maxBytes: 16 * 1024 }));
  } catch {
    fail("Agent Contract adapter wallet could not be read safely.");
  }
  if (!isPlainObject(wallet) || typeof wallet.privateKey !== "string" || !/^0x[0-9a-f]{64}$/.test(wallet.privateKey)) {
    fail("Agent Contract adapter wallet is invalid.");
  }
  const account = privateKeyToAccount(wallet.privateKey);
  if (
    typeof wallet.address !== "string" ||
    getAddress(wallet.address) !== account.address ||
    account.address !== config.address
  ) {
    fail("Agent Contract adapter wallet does not match the verified identity.");
  }
  return Object.freeze({ account, privateKey: wallet.privateKey });
}

function authorityDecision(config, proposal) {
  const mandate = {
    schema: "agent-contract/v1",
    mandateId: "mandate:provider:1",
    partyId: config.partyId,
    agentAddress: config.address,
    allowedActions: ["discover", "submit_firm_proposal"],
    maxContractValue: "100",
    issuedAt: "2026-08-01T00:00:00.000Z",
    expiresAt: "2026-09-01T00:00:00.000Z",
    revokedAt: null,
  };
  const now = Date.parse(strictIso(config.now()));
  if (now < Date.parse(mandate.issuedAt) || now >= Date.parse(mandate.expiresAt)) fail("Provider mandate is not active.");
  if (BigInt(proposal.price) > BigInt(mandate.maxContractValue)) fail("Proposal exceeds provider mandate.");
  return Object.freeze({
    allowed: true,
    proposalDigest: canonicalDigest(proposal),
    mandateDigest: canonicalDigest(mandate),
  });
}

function proposalFromArguments(config, value) {
  const args = exactObject(value, ["deliverableSummary", "formats", "deliveryHours", "price", "verificationMethod"], "Proposal arguments");
  if (
    typeof args.deliverableSummary !== "string" || args.deliverableSummary.trim().length === 0 ||
    !Array.isArray(args.formats) || args.formats.length < 1 || args.formats.length > 2 ||
    new Set(args.formats).size !== args.formats.length ||
    args.formats.some((entry) => !["json", "markdown"].includes(entry)) ||
    !Number.isSafeInteger(args.deliveryHours) || args.deliveryHours < 1 || args.deliveryHours > 24 ||
    typeof args.price !== "string" || !INTEGER.test(args.price) || BigInt(args.price) > 20n ||
    args.verificationMethod !== "checksum-and-required-sections/v1"
  ) fail("Proposal arguments are invalid.");
  return Object.freeze({
    schema: "agent-contract/v1",
    proposalId: `proposal:${randomUUID()}`,
    opportunityId: config.opportunityId,
    providerPartyId: config.partyId,
    deliverableSummary: args.deliverableSummary.trim(),
    formats: Object.freeze([...args.formats]),
    deliveryHours: args.deliveryHours,
    price: args.price,
    verificationMethod: args.verificationMethod,
    predecessorDigest: null,
  });
}

async function signedMessage({ account, config, data, recipientRole, predecessorMessageDigest, authorityDecisionDigest }) {
  const messageId = randomUUID();
  const sentAt = strictIso(config.now());
  const unsignedBinding = {
    schema: "agent-contract.a2a-trust-binding/v1",
    sessionId: config.sessionId,
    certificateDigest: config.certificateDigest,
    continuationDigest: config.continuationDigest,
    senderRole: config.role,
    senderAddress: config.address,
    senderErc8004AgentId: config.erc8004AgentId,
    recipientRole,
    objectDigest: canonicalDigest(data),
    predecessorMessageDigest,
    authorityDecisionDigest,
    sentAt,
  };
  const signature = await account.signMessage({
    message: canonicalJson({ ...unsignedBinding, messageId, contextId: config.sessionId }),
  });
  return Object.freeze({
    messageId,
    contextId: config.sessionId,
    role: "ROLE_USER",
    parts: Object.freeze([Object.freeze({ data })]),
    metadata: Object.freeze({ clockchainTrust: Object.freeze({ ...unsignedBinding, signature }) }),
  });
}

async function requestJson(config, path, { method = "GET", body, a2a = false } = {}) {
  const response = await config.fetchImpl(`${config.baseUrl}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${config.roleCapability}`,
      ...(body === undefined ? {} : { "content-type": a2a ? "application/a2a+json" : "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
  });
  if (response?.ok !== true || typeof response.json !== "function") {
    const status = Number.isSafeInteger(response?.status) ? response.status : 0;
    throw new Error(`Agent Contract request failed safely (${status}).`);
  }
  let parsed;
  try {
    parsed = await response.json();
  } catch {
    throw new Error("Agent Contract response was invalid.");
  }
  return publicJson(parsed, [config.roleCapability]);
}

function taskMessage(task) {
  if (!isPlainObject(task) || !UUID.test(task.id ?? "") || !Array.isArray(task.history) || task.history.length !== 1) {
    fail("Agent Contract inbox task is invalid.");
  }
  const message = task.history[0];
  if (!isPlainObject(message) || message.contextId !== task.contextId || message.contextId === undefined) {
    fail("Agent Contract inbox message is invalid.");
  }
  return message;
}

export async function createAgentContractA2AAdapter(input = {}) {
  const config = validateConfig(input);
  const wallet = await readWallet(config);
  const canaries = Object.freeze([wallet.privateKey, config.roleCapability, config.walletPath]);
  const path = (suffix) => `/api/a2a/sessions/${config.sessionId}${suffix}`;

  async function callTool(name, args = {}) {
    if (name === "agent_contract_discover_counterparty") {
      exactObject(args, [], "Discovery arguments");
      const target = config.role === "provider" ? "buyer" : "provider";
      return requestJson(config, path(`/agents/${target}/card`));
    }
    if (name === "agent_contract_read_inbox") {
      exactObject(args, [], "Inbox arguments");
      return requestJson(config, path(`/agents/${config.role}/inbox`));
    }
    if (name === "agent_contract_send_proposal") {
      if (config.role !== "provider") fail("Only the provider role may send a proposal.");
      const proposal = proposalFromArguments(config, args);
      const decision = authorityDecision(config, proposal);
      const data = Object.freeze({ kind: "firm_proposal", proposal });
      const message = await signedMessage({
        account: wallet.account,
        config,
        data,
        recipientRole: "buyer",
        predecessorMessageDigest: null,
        authorityDecisionDigest: canonicalDigest(decision),
      });
      return publicJson(await requestJson(config, path("/agents/buyer/message:send"), {
        method: "POST",
        body: { message },
        a2a: true,
      }), canaries);
    }
    if (name === "agent_contract_acknowledge_proposal") {
      if (config.role !== "buyer") fail("Only the buyer role may acknowledge a proposal.");
      const clean = exactObject(args, ["taskId", "decision"], "Acknowledgment arguments");
      if (!UUID.test(clean.taskId ?? "") || clean.decision !== "received_for_review") fail("Acknowledgment arguments are invalid.");
      const inbox = await requestJson(config, path("/agents/buyer/inbox"));
      if (!Array.isArray(inbox)) fail("Agent Contract inbox is invalid.");
      const task = inbox.find((entry) => entry?.id === clean.taskId);
      if (task === undefined) fail("The proposal task was not found in the authenticated buyer inbox.");
      const proposalMessage = taskMessage(task);
      const proposalData = proposalMessage?.parts?.[0]?.data;
      if (proposalData?.kind !== "firm_proposal" || !isPlainObject(proposalData.proposal)) fail("The stored task is not a firm proposal.");
      const data = Object.freeze({
        kind: "proposal_acknowledgment",
        decision: "received_for_review",
        binding: false,
        proposalDigest: canonicalDigest(proposalData.proposal),
      });
      const message = await signedMessage({
        account: wallet.account,
        config,
        data,
        recipientRole: "provider",
        predecessorMessageDigest: canonicalDigest(proposalMessage),
        authorityDecisionDigest: null,
      });
      return publicJson(await requestJson(config, path("/agents/provider/message:send"), {
        method: "POST",
        body: { message },
        a2a: true,
      }), canaries);
    }
    fail("Unknown Agent Contract A2A tool.");
  }

  return Object.freeze({
    tools: AGENT_CONTRACT_A2A_TOOLS,
    callTool,
    canonicalJson,
    canonicalDigest,
  });
}

export function runAgentContractA2AMcpServer({ adapter, input = process.stdin, output = process.stdout } = {}) {
  if (adapter === null || typeof adapter?.callTool !== "function" || typeof output?.write !== "function") {
    fail("Agent Contract MCP adapter is invalid.");
  }
  const send = (value) => output.write(`${JSON.stringify(value)}\n`);
  const lineReader = readline.createInterface({ input, crlfDelay: Infinity });
  lineReader.on("line", async (line) => {
    let request;
    try { request = JSON.parse(line); } catch { return; }
    const { id } = request;
    if (request.method === "initialize") {
      send({ jsonrpc: "2.0", id, result: {
        protocolVersion: request.params?.protocolVersion ?? "2025-06-18",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "agent-contract-a2a-adapter", version: "1.0.0" },
      } });
      return;
    }
    if (request.method === "notifications/initialized" || request.method === "notifications/cancelled") return;
    if (request.method === "tools/list") {
      send({ jsonrpc: "2.0", id, result: { tools: AGENT_CONTRACT_A2A_TOOLS } });
      return;
    }
    if (request.method === "tools/call") {
      try {
        const value = await adapter.callTool(request.params?.name, request.params?.arguments ?? {});
        send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(value) }], isError: false } });
      } catch {
        send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: "Agent Contract action failed safely." }], isError: true } });
      }
      return;
    }
    if (id !== undefined) send({ jsonrpc: "2.0", id, error: { code: -32601, message: "method not found" } });
  });
  return lineReader;
}

export function agentContractA2AConfigFromEnvironment(env = process.env) {
  const required = (name) => {
    const value = env[name];
    if (typeof value !== "string" || value.length === 0) fail(`Missing ${name}.`);
    return value;
  };
  return Object.freeze({
    role: required("AGENT_CONTRACT_A2A_ROLE"),
    baseUrl: required("AGENT_CONTRACT_A2A_BASE_URL"),
    sessionId: required("AGENT_CONTRACT_A2A_SESSION_ID"),
    certificateDigest: required("AGENT_CONTRACT_A2A_CERTIFICATE_DIGEST"),
    continuationDigest: required("AGENT_CONTRACT_A2A_CONTINUATION_DIGEST"),
    address: required("AGENT_CONTRACT_A2A_ADDRESS"),
    erc8004AgentId: required("AGENT_CONTRACT_A2A_ERC8004_AGENT_ID"),
    partyId: required("AGENT_CONTRACT_A2A_PARTY_ID"),
    opportunityId: required("AGENT_CONTRACT_A2A_OPPORTUNITY_ID"),
    roleCapability: required("AGENT_CONTRACT_A2A_ROLE_TOKEN"),
    walletPath: required("AGENT_CONTRACT_A2A_WALLET_PATH"),
    fetchImpl: globalThis.fetch,
    now: () => new Date().toISOString(),
  });
}

async function main() {
  if (process.argv.length !== 3 || process.argv[2] !== "--stdio") fail("Agent Contract A2A adapter invocation invalid.");
  const adapter = await createAgentContractA2AAdapter(agentContractA2AConfigFromEnvironment());
  runAgentContractA2AMcpServer({ adapter });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch(() => {
    process.stderr.write("Agent Contract A2A adapter failed safely.\n");
    process.exitCode = 1;
  });
}
