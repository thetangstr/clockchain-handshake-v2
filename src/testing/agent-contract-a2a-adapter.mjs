import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute } from "node:path";
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
  Object.freeze({
    name: "agent_contract_offer_gate_1_agreement",
    title: "Offer one binding Gate 1 agreement",
    description: "Provider only. Build, authorize, sign, and send the one sandbox Gate 1 agreement from an exact stored proposal acknowledgment.",
    inputSchema: Object.freeze({
      type: "object",
      additionalProperties: false,
      properties: Object.freeze({
        acknowledgmentTaskId: Object.freeze({ type: "string", format: "uuid" }),
      }),
      required: Object.freeze(["acknowledgmentTaskId"]),
    }),
  }),
  Object.freeze({
    name: "agent_contract_accept_gate_1_agreement",
    title: "Accept one binding Gate 1 agreement",
    description: "Buyer only. Validate, authorize, sign, and accept the exact stored Gate 1 agreement offer.",
    inputSchema: Object.freeze({
      type: "object",
      additionalProperties: false,
      properties: Object.freeze({
        offerTaskId: Object.freeze({ type: "string", format: "uuid" }),
      }),
      required: Object.freeze(["offerTaskId"]),
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
  const authority = input.agreementAuthority === undefined
    ? undefined
    : agreementAuthority(input.agreementAuthority, input.role, input.partyId, input.address);
  const witnessConfigured = input.runtimeId !== undefined || input.witnessLedgerPath !== undefined;
  if (witnessConfigured && (
    !UUID.test(input.runtimeId ?? "") ||
    typeof input.witnessLedgerPath !== "string" ||
    !isAbsolute(input.witnessLedgerPath) ||
    basename(input.witnessLedgerPath) !== ".agent-contract-a2a-witness.json" ||
    !isAbsolute(input.walletPath) ||
    dirname(input.witnessLedgerPath) !== dirname(input.walletPath)
  )) fail("Agent Contract witness ledger configuration is invalid.");
  return Object.freeze({
    ...input,
    agreementAuthority: authority,
    baseUrl: loopbackBaseUrl(input.baseUrl),
    address: getAddress(input.address),
    counterpartyAddress: input.counterpartyAddress === undefined ? undefined : getAddress(input.counterpartyAddress),
  });
}

function agreementAuthority(value, role, partyId, address) {
  const keys = [
    "schema", "authorityRef", "partyId", "signerAddress", "role", "allowedActions",
    "maxProviderServiceFeeAtomic", "assetChainId", "assetAddress", "issuedAt", "expiresAt",
    "revokedAt", "approvalSource",
  ];
  const grant = exactObject(value, keys, "Gate 1 agreement authority");
  const expectedRole = role === "provider" ? "PROVIDER" : "BUYER";
  if (
    grant.schema !== "agent-contract.gate-1-agreement-authority/v1" ||
    typeof grant.authorityRef !== "string" || grant.authorityRef.length === 0 ||
    grant.partyId !== partyId || getAddress(grant.signerAddress) !== getAddress(address) ||
    grant.role !== expectedRole || JSON.stringify(grant.allowedActions) !== JSON.stringify(["ACCEPT_GATE_1_AGREEMENT"]) ||
    !INTEGER.test(grant.maxProviderServiceFeeAtomic ?? "") ||
    grant.assetChainId !== "84532" ||
    String(grant.assetAddress).toLowerCase() !== "0x036cbd53842c5426634e7929541ec2318f3dcf7e" ||
    strictIso(grant.issuedAt) >= strictIso(grant.expiresAt) ||
    grant.revokedAt !== null || !["AGENT_MANDATE", "HUMAN_APPROVAL"].includes(grant.approvalSource)
  ) fail("Gate 1 agreement authority is invalid.");
  return Object.freeze({
    ...grant,
    signerAddress: getAddress(grant.signerAddress),
    assetAddress: String(grant.assetAddress).toLowerCase(),
    allowedActions: Object.freeze([...grant.allowedActions]),
  });
}

function createAuthorshipLedger(config, canaries) {
  if (config.witnessLedgerPath === undefined) {
    return Object.freeze({ record: async () => {} });
  }
  const entries = [];
  let created = false;
  return Object.freeze({
    async record(entry) {
      if (
        !isPlainObject(entry) ||
        (entry.kind !== "inbox_read" && entries.some((current) => current.kind === entry.kind))
      ) {
        fail("Agent Contract witness ledger entry is invalid.");
      }
      const next = Object.freeze({ ...entry, runtimeId: config.runtimeId });
      assertSecretFree(next, canaries);
      entries.push(next);
      const ledger = Object.freeze({
        schema: "agent-contract.a2a-authorship-ledger/v1",
        runtimeId: config.runtimeId,
        entries: Object.freeze([...entries]),
      });
      assertSecretFree(ledger, canaries);
      await writeFile(config.witnessLedgerPath, `${JSON.stringify(ledger)}\n`, {
        encoding: "utf8",
        flag: created ? "w" : "wx",
        mode: 0o600,
      });
      created = true;
    },
  });
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

function gate1Agreement(config, proposalDigest) {
  if (config.agreementAuthority === undefined || config.counterpartyAddress === undefined) fail("Gate 1 agreement authority is not configured.");
  const effectiveAt = strictIso(config.now());
  const authorityExpiry = Date.parse(config.agreementAuthority.expiresAt);
  const expiresAtMs = Math.min(Date.parse(effectiveAt) + 5 * 60 * 1000, authorityExpiry - 1);
  if (expiresAtMs <= Date.parse(effectiveAt)) fail("Gate 1 agreement authority is not active long enough.");
  return Object.freeze({
    schema: "agent-contract.gate-1-agreement/v1",
    agreementId: `agreement:gate-1:${config.sessionId}`,
    proposalDigest,
    buyerPartyId: "buyer:co",
    buyerAddress: config.role === "buyer" ? config.address : config.counterpartyAddress,
    providerPartyId: "provider:proofworks",
    providerAddress: config.role === "provider" ? config.address : config.counterpartyAddress,
    work: Object.freeze({
      service: "sandbox_cross_border_payment_execution",
      deliverable: "Execute one sandbox transfer and produce a redacted receipt pack",
      executionDeadline: new Date(Math.min(Date.parse(effectiveAt) + 4 * 60 * 1000, expiresAtMs)).toISOString(),
      principalIsSandboxOnly: true,
    }),
    providerServiceFee: Object.freeze({
      assetChainId: "84532",
      assetAddress: "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
      assetDecimals: 6,
      amountAtomic: "10000",
      separateFromCrossBorderPrincipal: true,
    }),
    payerObligations: Object.freeze([Object.freeze({
      obligationId: "payer-input:sandbox-beneficiary",
      description: "Provide sandbox beneficiary instructions",
      dueAt: new Date(Math.min(Date.parse(effectiveAt) + 2 * 60 * 1000, expiresAtMs)).toISOString(),
      acceptanceRequiredFromProvider: true,
    })]),
    providerInputAcknowledgment: Object.freeze({
      status: "SUFFICIENT",
      acknowledgedObligationIds: Object.freeze(["payer-input:sandbox-beneficiary"]),
      acknowledgedAt: effectiveAt,
    }),
    evidencePolicy: Object.freeze({
      policyId: "evidence:gate-1:001",
      policyDigest: canonicalDigest({ sessionId: config.sessionId, policy: "sandbox-transfer-receipt/v1" }),
      requiredEvidenceTypes: Object.freeze(["sandbox_transfer_receipt", "receipt_checksum"]),
    }),
    verificationPolicy: Object.freeze({
      policyId: "verification:gate-1:001",
      policyDigest: canonicalDigest({ sessionId: config.sessionId, policy: "sandbox-receipt-and-checksum/v1" }),
      evaluatorPartyId: "evaluator:gate-1",
      evaluatorAddress: `0x${"55".repeat(20)}`,
      method: "sandbox-receipt-and-checksum/v1",
    }),
    conditionalSettlement: Object.freeze({
      settlementRailId: "base-commerce-sepolia-test-usdc/v1",
      fundingRequiredBeforeExecution: true,
      captureOutcome: "PASS",
      voidOutcome: "FAIL",
      holdOutcomes: Object.freeze(["INDETERMINATE", "SYSTEM_ERROR"]),
      fullAmountOnly: true,
    }),
    effectiveAt,
    expiresAt: new Date(expiresAtMs).toISOString(),
    predecessorDigest: proposalDigest,
  });
}

function agreementDecision(config, agreement) {
  const grant = config.agreementAuthority;
  if (grant === undefined) fail("Gate 1 agreement authority is not configured.");
  const now = Date.parse(strictIso(config.now()));
  if (
    now < Date.parse(grant.issuedAt) || now >= Date.parse(grant.expiresAt) ||
    grant.partyId !== config.partyId || getAddress(grant.signerAddress) !== config.address ||
    (grant.role === "BUYER" ? getAddress(agreement.buyerAddress) : getAddress(agreement.providerAddress)) !== config.address ||
    BigInt(agreement.providerServiceFee.amountAtomic) > BigInt(grant.maxProviderServiceFeeAtomic) ||
    agreement.providerServiceFee.assetChainId !== grant.assetChainId ||
    agreement.providerServiceFee.assetAddress !== grant.assetAddress
  ) fail("Gate 1 agreement authority denied.");
  return Object.freeze({
    allowed: true,
    role: grant.role,
    agreementDigest: canonicalDigest(agreement),
    authorityDigest: canonicalDigest(grant),
    authorityRef: grant.authorityRef,
    approvalSource: grant.approvalSource,
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
  const ledger = createAuthorshipLedger(config, canaries);
  const path = (suffix) => `/api/a2a/sessions/${config.sessionId}${suffix}`;

  async function callTool(name, args = {}) {
    if (name === "agent_contract_discover_counterparty") {
      exactObject(args, [], "Discovery arguments");
      const target = config.role === "provider" ? "buyer" : "provider";
      const card = await requestJson(config, path(`/agents/${target}/card`));
      await ledger.record({
        kind: "agent_card_discovered",
        toolName: name,
        argumentsDigest: canonicalDigest({}),
        occurredAt: strictIso(config.now()),
      });
      return card;
    }
    if (name === "agent_contract_read_inbox") {
      exactObject(args, [], "Inbox arguments");
      const inbox = await requestJson(config, path(`/agents/${config.role}/inbox`));
      await ledger.record({
        kind: "inbox_read",
        toolName: name,
        argumentsDigest: canonicalDigest({}),
        occurredAt: strictIso(config.now()),
      });
      return inbox;
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
      const task = publicJson(await requestJson(config, path("/agents/buyer/message:send"), {
        method: "POST",
        body: { message },
        a2a: true,
      }), canaries);
      const persistedMessage = taskMessage(task);
      const objectDigest = canonicalDigest(data);
      if (
        persistedMessage.metadata?.clockchainTrust?.objectDigest !== objectDigest ||
        persistedMessage.metadata.clockchainTrust.predecessorMessageDigest !== null
      ) fail("Persisted proposal evidence is invalid.");
      await ledger.record({
        kind: "proposal_authorship",
        toolName: name,
        argumentsDigest: objectDigest,
        persistedObjectDigest: persistedMessage.metadata.clockchainTrust.objectDigest,
        messageDigest: canonicalDigest(persistedMessage),
        predecessorMessageDigest: null,
        authoredAt: strictIso(message.metadata.clockchainTrust.sentAt),
        persistedAt: strictIso(config.now()),
      });
      return task;
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
      const persistedTask = publicJson(await requestJson(config, path("/agents/provider/message:send"), {
        method: "POST",
        body: { message },
        a2a: true,
      }), canaries);
      const persistedMessage = taskMessage(persistedTask);
      const objectDigest = canonicalDigest(data);
      if (
        persistedMessage.metadata?.clockchainTrust?.objectDigest !== objectDigest ||
        persistedMessage.metadata.clockchainTrust.predecessorMessageDigest !==
          canonicalDigest(proposalMessage)
      ) fail("Persisted acknowledgment evidence is invalid.");
      await ledger.record({
        kind: "acknowledgment_authorship",
        toolName: name,
        argumentsDigest: objectDigest,
        persistedObjectDigest: persistedMessage.metadata.clockchainTrust.objectDigest,
        messageDigest: canonicalDigest(persistedMessage),
        predecessorMessageDigest:
          persistedMessage.metadata.clockchainTrust.predecessorMessageDigest,
        authoredAt: strictIso(message.metadata.clockchainTrust.sentAt),
        persistedAt: strictIso(config.now()),
      });
      return persistedTask;
    }
    if (name === "agent_contract_offer_gate_1_agreement") {
      if (config.role !== "provider") fail("Only the provider role may offer a Gate 1 agreement.");
      const clean = exactObject(args, ["acknowledgmentTaskId"], "Agreement offer arguments");
      if (!UUID.test(clean.acknowledgmentTaskId ?? "")) fail("Agreement offer arguments are invalid.");
      const inbox = await requestJson(config, path("/agents/provider/inbox"));
      if (!Array.isArray(inbox)) fail("Agent Contract inbox is invalid.");
      const task = inbox.find((entry) => entry?.id === clean.acknowledgmentTaskId);
      if (task === undefined) fail("The proposal acknowledgment was not found in the authenticated provider inbox.");
      const acknowledgmentMessage = taskMessage(task);
      const acknowledgment = acknowledgmentMessage?.parts?.[0]?.data;
      if (
        acknowledgment?.kind !== "proposal_acknowledgment" ||
        acknowledgment.binding !== false || !DIGEST.test(acknowledgment.proposalDigest ?? "")
      ) fail("The stored task is not a valid proposal acknowledgment.");
      const agreement = gate1Agreement(config, acknowledgment.proposalDigest);
      const decision = agreementDecision(config, agreement);
      const data = Object.freeze({
        kind: "agreement_offer",
        agreement,
        agreementDigest: canonicalDigest(agreement),
        binding: true,
        providerAcceptance: "ACCEPTED",
      });
      const message = await signedMessage({
        account: wallet.account,
        config,
        data,
        recipientRole: "buyer",
        predecessorMessageDigest: canonicalDigest(acknowledgmentMessage),
        authorityDecisionDigest: canonicalDigest(decision),
      });
      const persistedTask = publicJson(await requestJson(config, path("/agents/buyer/message:send"), {
        method: "POST",
        body: { message },
        a2a: true,
      }), canaries);
      const persistedMessage = taskMessage(persistedTask);
      if (
        persistedMessage.metadata?.clockchainTrust?.objectDigest !== canonicalDigest(data) ||
        persistedMessage.metadata.clockchainTrust.predecessorMessageDigest !== canonicalDigest(acknowledgmentMessage) ||
        persistedMessage.metadata.clockchainTrust.authorityDecisionDigest !== canonicalDigest(decision)
      ) fail("Persisted agreement offer evidence is invalid.");
      await ledger.record({
        kind: "agreement_offer_authorship",
        toolName: name,
        argumentsDigest: canonicalDigest(data),
        persistedObjectDigest: persistedMessage.metadata.clockchainTrust.objectDigest,
        messageDigest: canonicalDigest(persistedMessage),
        predecessorMessageDigest: persistedMessage.metadata.clockchainTrust.predecessorMessageDigest,
        authorityDecisionDigest: persistedMessage.metadata.clockchainTrust.authorityDecisionDigest,
        authoredAt: strictIso(message.metadata.clockchainTrust.sentAt),
        persistedAt: strictIso(config.now()),
      });
      return persistedTask;
    }
    if (name === "agent_contract_accept_gate_1_agreement") {
      if (config.role !== "buyer") fail("Only the buyer role may accept a Gate 1 agreement.");
      if (config.agreementAuthority === undefined || config.counterpartyAddress === undefined) fail("Gate 1 agreement authority is not configured.");
      const clean = exactObject(args, ["offerTaskId"], "Agreement acceptance arguments");
      if (!UUID.test(clean.offerTaskId ?? "")) fail("Agreement acceptance arguments are invalid.");
      const inbox = await requestJson(config, path("/agents/buyer/inbox"));
      if (!Array.isArray(inbox)) fail("Agent Contract inbox is invalid.");
      const task = inbox.find((entry) => entry?.id === clean.offerTaskId);
      if (task === undefined) fail("The agreement offer was not found in the authenticated buyer inbox.");
      const offerMessage = taskMessage(task);
      const offer = offerMessage?.parts?.[0]?.data;
      if (
        offer?.kind !== "agreement_offer" || offer.binding !== true ||
        !isPlainObject(offer.agreement) || offer.agreementDigest !== canonicalDigest(offer.agreement) ||
        getAddress(offer.agreement.buyerAddress) !== config.address ||
        getAddress(offer.agreement.providerAddress) !== config.counterpartyAddress
      ) fail("The stored task is not a valid Gate 1 agreement offer.");
      const decision = agreementDecision(config, offer.agreement);
      const data = Object.freeze({
        kind: "agreement_acceptance",
        agreementId: offer.agreement.agreementId,
        agreementDigest: offer.agreementDigest,
        decision: "ACCEPTED",
        binding: true,
      });
      const message = await signedMessage({
        account: wallet.account,
        config,
        data,
        recipientRole: "provider",
        predecessorMessageDigest: canonicalDigest(offerMessage),
        authorityDecisionDigest: canonicalDigest(decision),
      });
      const persistedTask = publicJson(await requestJson(config, path("/agents/provider/message:send"), {
        method: "POST",
        body: { message },
        a2a: true,
      }), canaries);
      const persistedMessage = taskMessage(persistedTask);
      if (
        persistedMessage.metadata?.clockchainTrust?.objectDigest !== canonicalDigest(data) ||
        persistedMessage.metadata.clockchainTrust.predecessorMessageDigest !== canonicalDigest(offerMessage) ||
        persistedMessage.metadata.clockchainTrust.authorityDecisionDigest !== canonicalDigest(decision)
      ) fail("Persisted agreement acceptance evidence is invalid.");
      await ledger.record({
        kind: "agreement_acceptance_authorship",
        toolName: name,
        argumentsDigest: canonicalDigest(data),
        persistedObjectDigest: persistedMessage.metadata.clockchainTrust.objectDigest,
        messageDigest: canonicalDigest(persistedMessage),
        predecessorMessageDigest: persistedMessage.metadata.clockchainTrust.predecessorMessageDigest,
        authorityDecisionDigest: persistedMessage.metadata.clockchainTrust.authorityDecisionDigest,
        authoredAt: strictIso(message.metadata.clockchainTrust.sentAt),
        persistedAt: strictIso(config.now()),
      });
      return persistedTask;
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
  const witnessValues = [
    env.AGENT_CONTRACT_A2A_RUNTIME_ID,
    env.AGENT_CONTRACT_A2A_WITNESS_LEDGER_PATH,
  ];
  if (witnessValues.some((entry) => entry !== undefined) && witnessValues.some((entry) => entry === undefined)) {
    fail("Agent Contract witness ledger environment is incomplete.");
  }
  return Object.freeze({
    role: required("AGENT_CONTRACT_A2A_ROLE"),
    baseUrl: required("AGENT_CONTRACT_A2A_BASE_URL"),
    sessionId: required("AGENT_CONTRACT_A2A_SESSION_ID"),
    certificateDigest: required("AGENT_CONTRACT_A2A_CERTIFICATE_DIGEST"),
    continuationDigest: required("AGENT_CONTRACT_A2A_CONTINUATION_DIGEST"),
    address: required("AGENT_CONTRACT_A2A_ADDRESS"),
    counterpartyAddress: env.AGENT_CONTRACT_A2A_COUNTERPARTY_ADDRESS,
    erc8004AgentId: required("AGENT_CONTRACT_A2A_ERC8004_AGENT_ID"),
    partyId: required("AGENT_CONTRACT_A2A_PARTY_ID"),
    opportunityId: required("AGENT_CONTRACT_A2A_OPPORTUNITY_ID"),
    roleCapability: required("AGENT_CONTRACT_A2A_ROLE_TOKEN"),
    agreementAuthority: env.AGENT_CONTRACT_A2A_AGREEMENT_AUTHORITY === undefined ? undefined : (() => {
      try {
        return JSON.parse(required("AGENT_CONTRACT_A2A_AGREEMENT_AUTHORITY"));
      } catch {
        fail("Invalid AGENT_CONTRACT_A2A_AGREEMENT_AUTHORITY.");
      }
    })(),
    walletPath: required("AGENT_CONTRACT_A2A_WALLET_PATH"),
    ...(witnessValues[0] === undefined
      ? {}
      : {
          runtimeId: required("AGENT_CONTRACT_A2A_RUNTIME_ID"),
          witnessLedgerPath: required("AGENT_CONTRACT_A2A_WITNESS_LEDGER_PATH"),
        }),
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
