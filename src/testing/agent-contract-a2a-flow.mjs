import { assertSecretFree } from "../core/redact.mjs";
import { getAddress } from "viem";
import { canonicalDigest } from "./agent-contract-a2a-adapter.mjs";

const RESULT_SCHEMA = "agent-contract.facilitated-a2a-result/v1";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const INTEGER = /^(?:0|[1-9][0-9]*)$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1", "localhost"]);
export const FACILITATED_A2A_SCOPE = "single_provider_proposal_nonbinding_buyer_acknowledgment";
export const FACILITATED_A2A_VALID_FOR_SECONDS = "600";
export const FACILITATED_A2A_AUTHORIZATION_STATEMENT = "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.";
const VERIFICATION_KEYS = Object.freeze([
  "identityContinuity",
  "providerDiscoveredBuyerCard",
  "proposalSignatureVerified",
  "proposalAuthorityVerified",
  "buyerAcknowledgmentVerified",
  "predecessorBindingVerified",
]);

const PROVIDER_PROMPT = `The Clockchain handshake is already verified. Continue as the provider through the configured Agent Contract A2A tools. First discover the buyer Agent Card. The buyer opportunity requests one signed evidence pack in both lowercase platform formats, json and markdown, delivered within 24 hours, at a price no greater than 20, using checksum-and-required-sections/v1 verification. Independently choose the deliverable summary, delivery time, and price within that opportunity and your mandate, then call the proposal tool yourself. Do not claim negotiation, agreement, payment, escrow, or external execution.`;

const BUYER_PROMPT = `The Clockchain handshake is already verified. Continue as the buyer through the configured Agent Contract A2A tools. Call agent_contract_read_inbox to read your authenticated inbox, then evaluate the exact stored proposal against your opportunity: one signed evidence pack in both lowercase platform formats, json and markdown, delivered within 24 hours, at a price no greater than 20, using checksum-and-required-sections/v1 verification. Independently compare the stored proposal with those requirements. If it matches, call agent_contract_acknowledge_proposal yourself with the exact stored taskId and decision received_for_review to record only that it was received for review. The acknowledgment must remain nonbinding. Do not finish until you have either issued that signed nonbinding acknowledgment or stated the concrete requirement mismatch. Do not accept terms, create an agreement, authorize payment, or claim escrow or execution.`;

function fail(message) {
  throw new Error(message);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function loopbackBaseUrl(value) {
  let parsed;
  try { parsed = new URL(value); } catch { fail("Agent Contract A2A base URL invalid."); }
  if (
    parsed.protocol !== "http:" || !LOOPBACK_HOSTS.has(parsed.hostname) ||
    parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "" ||
    !["", "/"].includes(parsed.pathname)
  ) fail("Agent Contract A2A base URL must be loopback HTTP.");
  return parsed.origin;
}

function strictIso(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) fail("Agent Contract A2A time invalid.");
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) fail("Agent Contract A2A time invalid.");
  return value;
}

function roleEvidence(value, role) {
  if (
    !isPlainObject(value) || value.role !== role || !ADDRESS.test(value.address ?? "") ||
    value.certificateVerified !== true || !HASH.test(value.certificateDigest ?? "") ||
    value.externalBusinessActionPerformed !== false || !isPlainObject(value.erc8004) ||
    !INTEGER.test(value.erc8004.agentId ?? "") || typeof value.erc8004.reference !== "string" ||
    value.erc8004.reference.length === 0
  ) fail("Continuum role evidence invalid.");
  return Object.freeze({ ...value, address: getAddress(value.address) });
}

function validateEvidence(value) {
  const buyer = roleEvidence(value?.roles?.initiator, "initiator");
  const provider = roleEvidence(value?.roles?.responder, "responder");
  if (
    value?.schema !== "clockchain.fresh-agent-canary-evidence/v1" || value.certificateVerified !== true ||
    value?.clients?.initiator !== "codex" || value?.clients?.responder !== "claude" ||
    !UUID.test(value?.monitor?.sessionId ?? "") || value.monitor.sessionId !== buyer.sessionId ||
    value.monitor.sessionId !== provider.sessionId || !HASH.test(value?.binding?.certificateDigest ?? "") ||
    buyer.certificateDigest !== value.binding.certificateDigest || provider.certificateDigest !== value.binding.certificateDigest ||
    value?.monitor?.certificate?.digest !== value.binding.certificateDigest ||
    !Number.isSafeInteger(value?.monitor?.certificate?.issuedAtMs) ||
    !Number.isSafeInteger(value?.binding?.sessionDeadlineMs) ||
    value.monitor.certificate.issuedAtMs >= value.binding.sessionDeadlineMs ||
    value?.monitor?.terms?.statement !== FACILITATED_A2A_AUTHORIZATION_STATEMENT ||
    value.monitor.terms.validForSeconds !== "90" ||
    value.monitor.terms.statementDigest !== value.binding.statementDigest ||
    buyer.address === provider.address || buyer.erc8004.agentId === provider.erc8004.agentId
  ) fail("Continuum handshake evidence invalid for A2A continuation.");
  return Object.freeze({ value, buyer, provider });
}

function continuumReceipt(value, kind) {
  if (
    value?.kind !== kind || !UUID.test(value?.ledgerId ?? "") || !HASH.test(value?.digest ?? "") ||
    !INTEGER.test(value?.blockHeight ?? "") || typeof value?.blockTimeRaw !== "string" ||
    typeof value?.explorerUrl !== "string"
  ) fail("Continuum receipt evidence invalid.");
  return value;
}

function handshakeEvidence(validated) {
  const { value, buyer, provider } = validated;
  const receipts = [
    continuumReceipt(value.monitor.receipts.proposal, "proposal"),
    continuumReceipt(value.monitor.receipts.acceptance, "acceptance"),
    continuumReceipt(value.monitor.receipts.acknowledgment, "acknowledgment"),
  ];
  return Object.freeze({
    schema: "agent-contract/v1",
    sessionId: value.monitor.sessionId,
    certificateDigest: `0x${value.binding.certificateDigest}`,
    parties: ["buyer:co", "provider:proofworks"],
    verifications: [
      {
        agentAddress: buyer.address,
        method: "continuum_native_certificate",
        role: "initiator",
        client: "codex",
        certificateVerified: true,
        erc8004Reference: buyer.erc8004.reference,
      },
      {
        agentAddress: provider.address,
        method: "continuum_native_certificate",
        role: "responder",
        client: "claude",
        certificateVerified: true,
        erc8004Reference: provider.erc8004.reference,
      },
    ],
    issuedAt: new Date(value.monitor.certificate.issuedAtMs).toISOString(),
    expiresAt: new Date(value.binding.sessionDeadlineMs).toISOString(),
    sourceTool: "agent_handshake_get_certificate",
    provenance: "live_mcp",
    continuum: {
      sourceSchema: value.schema,
      runId: value.runId,
      sessionId: value.monitor.sessionId,
      certificateDigest: `0x${value.binding.certificateDigest}`,
      issuedAt: new Date(value.monitor.certificate.issuedAtMs).toISOString(),
      expiresAt: new Date(value.binding.sessionDeadlineMs).toISOString(),
      verifierAddresses: [buyer.address, provider.address],
      repositorySha: value.binding.repositorySha,
      statementDigest: value.binding.statementDigest,
      hostRootFingerprint: value.binding.hostRootFingerprint,
      hostSessionKeyCertificateDigest: value.binding.hostSessionKeyCertificateDigest,
      receipts,
      externalBusinessActionPerformed: false,
    },
    facilitatedA2AAuthorization: {
      schema: "agent-contract.facilitated-a2a-authorization/v1",
      scope: FACILITATED_A2A_SCOPE,
      validForSeconds: FACILITATED_A2A_VALID_FOR_SECONDS,
      statement: FACILITATED_A2A_AUTHORIZATION_STATEMENT,
      statementDigest: value.binding.statementDigest,
    },
  });
}

async function requestJson(fetchImpl, url, { method = "GET", token, body, a2a = false } = {}) {
  const response = await fetchImpl(url, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { "content-type": a2a ? "application/a2a+json" : "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
  });
  if (response?.ok !== true || typeof response.json !== "function") {
    throw new Error(`Agent Contract A2A request failed safely (${Number.isSafeInteger(response?.status) ? response.status : 0}).`);
  }
  try { return await response.json(); } catch { fail("Agent Contract A2A response invalid."); }
}

function activation(value, expectedSessionId) {
  if (
    !isPlainObject(value) || value.sessionId !== expectedSessionId || !isPlainObject(value.capabilities) ||
    typeof value.capabilities.buyer !== "string" || value.capabilities.buyer.length === 0 ||
    typeof value.capabilities.provider !== "string" || value.capabilities.provider.length === 0 ||
    value.capabilities.buyer === value.capabilities.provider ||
    !isPlainObject(value.authorization) || !/^0x[0-9a-f]{64}$/.test(value.authorization.digest ?? "") ||
    value.authorization.scope !== FACILITATED_A2A_SCOPE ||
    typeof value.authorization.expiresAt !== "string"
  ) fail("Agent Contract A2A activation invalid.");
  return value;
}

function environment({ baseUrl, sessionId, certificateDigest, continuationDigest, role, identity, partyId, token }) {
  return Object.freeze({
    AGENT_CONTRACT_A2A_BASE_URL: baseUrl,
    AGENT_CONTRACT_A2A_ROLE: role,
    AGENT_CONTRACT_A2A_SESSION_ID: sessionId,
    AGENT_CONTRACT_A2A_CERTIFICATE_DIGEST: certificateDigest,
    AGENT_CONTRACT_A2A_CONTINUATION_DIGEST: continuationDigest,
    AGENT_CONTRACT_A2A_ADDRESS: identity.address,
    AGENT_CONTRACT_A2A_ERC8004_AGENT_ID: identity.erc8004.agentId,
    AGENT_CONTRACT_A2A_PARTY_ID: partyId,
    AGENT_CONTRACT_A2A_OPPORTUNITY_ID: "opportunity:1",
    AGENT_CONTRACT_A2A_ROLE_TOKEN: token,
  });
}

function singleProposalTask(value, sessionId) {
  if (!Array.isArray(value)) fail("Agent Contract did not return an inbox.");
  const proposals = value.filter((task) =>
    task?.contextId === sessionId && task?.history?.[0]?.parts?.[0]?.data?.kind === "firm_proposal");
  if (proposals.length !== 1 || !UUID.test(proposals[0]?.id ?? "")) {
    fail("Agent Contract must store exactly one proposal before buyer continuation.");
  }
  return proposals[0];
}

function validateExport(value, validated, proposalTaskId, continuationDigest) {
  const { buyer, provider } = validated;
  const session = value?.session;
  const verification = value?.verification;
  if (
    value?.schema !== "agent-contract.facilitated-a2a-export/v1" ||
    value.provenance !== "live_a2a_facilitator" || session?.sessionId !== buyer.sessionId ||
    session?.certificate?.digest !== `0x${buyer.certificateDigest}` ||
    session?.authorization?.digest !== continuationDigest ||
    session?.participants?.buyer?.address !== buyer.address ||
    session?.participants?.provider?.address !== provider.address ||
    session?.participants?.buyer?.erc8004AgentId !== buyer.erc8004.agentId ||
    session?.participants?.provider?.erc8004AgentId !== provider.erc8004.agentId ||
    session?.participants?.buyer?.client !== "codex" ||
    session?.participants?.provider?.client !== "claude" ||
    !isPlainObject(verification) || VERIFICATION_KEYS.some((key) => verification[key] !== true) ||
    !Array.isArray(session.tasks)
  ) fail("Agent Contract final export does not preserve verified identity and provenance.");
  const proposal = session.tasks.find((task) => task?.id === proposalTaskId && task?.history?.[0]?.parts?.[0]?.data?.kind === "firm_proposal");
  const acknowledgments = session.tasks.filter((task) => task?.history?.[0]?.parts?.[0]?.data?.kind === "proposal_acknowledgment");
  if (proposal === undefined || acknowledgments.length !== 1 || !UUID.test(acknowledgments[0]?.id ?? "") || acknowledgments[0]?.history?.[0]?.parts?.[0]?.data?.binding !== false) {
    fail("Agent Contract final export is missing the exact proposal and nonbinding acknowledgment.");
  }
  return Object.freeze({
    verification: Object.freeze(Object.fromEntries(VERIFICATION_KEYS.map((key) => [key, true]))),
    acknowledgmentTaskId: acknowledgments[0].id,
    proposal,
    acknowledgment: acknowledgments[0],
  });
}

function witnessSource(value) {
  if (
    !isPlainObject(value) ||
    !/^[0-9a-f]{40}$/.test(value.agentContractCommit ?? "") ||
    !/^[0-9a-f]{40}$/.test(value.continuumCommit ?? "")
  ) fail("Live runtime witness source invalid.");
  return Object.freeze({
    agentContractCommit: value.agentContractCommit,
    continuumCommit: value.continuumCommit,
  });
}

function exactRuntimeContinuation(value, {
  client,
  modelId,
  requiredTools,
  ledgerKinds,
}) {
  if (
    value?.completed !== true || !isPlainObject(value.runtime) ||
    value.runtime.client !== client || value.runtime.modelId !== modelId ||
    !UUID.test(value.runtime.runtimeId ?? "") ||
    !/^0x[0-9a-f]{64}$/.test(value.runtime.processDigest ?? "") ||
    !isPlainObject(value.activity) || !Array.isArray(value.activity.tools) ||
    requiredTools.some((tool) => !value.activity.tools.includes(tool)) ||
    !isPlainObject(value.ledger) ||
    value.ledger.schema !== "agent-contract.a2a-authorship-ledger/v1" ||
    value.ledger.runtimeId !== value.runtime.runtimeId ||
    !Array.isArray(value.ledger.entries) ||
    JSON.stringify(value.ledger.entries.map((entry) => entry?.kind)) !==
      JSON.stringify(ledgerKinds) ||
    value.ledger.entries.some((entry) => entry?.runtimeId !== value.runtime.runtimeId)
  ) fail("Live runtime continuation evidence invalid.");
  return value;
}

function taskMessageForWitness(task) {
  if (!isPlainObject(task) || !Array.isArray(task.history) || task.history.length !== 1) {
    fail("Live runtime persisted task invalid.");
  }
  return task.history[0];
}

function buildLiveRuntimeWitness({
  completedAt,
  evidence,
  source,
  activationAt,
  providerContinuation,
  buyerContinuation,
  verified,
}) {
  const provider = exactRuntimeContinuation(providerContinuation, {
    client: "claude-code",
    modelId: "sonnet",
    requiredTools: ["agent_contract_discover_counterparty", "agent_contract_send_proposal"],
    ledgerKinds: ["agent_card_discovered", "proposal_authorship"],
  });
  const buyer = exactRuntimeContinuation(buyerContinuation, {
    client: "codex-cli",
    modelId: "gpt-5.6-terra",
    requiredTools: ["agent_contract_read_inbox", "agent_contract_acknowledge_proposal"],
    ledgerKinds: ["inbox_read", "acknowledgment_authorship"],
  });
  if (
    provider.runtime.runtimeId === buyer.runtime.runtimeId ||
    provider.runtime.processDigest === buyer.runtime.processDigest
  ) fail("Live runtime processes must be distinct.");

  const discovery = provider.ledger.entries[0];
  const proposalRecord = provider.ledger.entries[1];
  const acknowledgmentRecord = buyer.ledger.entries[1];
  const proposalMessage = taskMessageForWitness(verified.proposal);
  const acknowledgmentMessage = taskMessageForWitness(verified.acknowledgment);
  const proposalObjectDigest = proposalMessage?.metadata?.clockchainTrust?.objectDigest;
  const acknowledgmentObjectDigest = acknowledgmentMessage?.metadata?.clockchainTrust?.objectDigest;
  const proposalMessageDigest = canonicalDigest(proposalMessage);
  const acknowledgmentMessageDigest = canonicalDigest(acknowledgmentMessage);
  if (
    proposalRecord.toolName !== "agent_contract_send_proposal" ||
    proposalRecord.argumentsDigest !== proposalObjectDigest ||
    proposalRecord.persistedObjectDigest !== proposalObjectDigest ||
    proposalRecord.messageDigest !== proposalMessageDigest ||
    proposalRecord.predecessorMessageDigest !== null ||
    acknowledgmentRecord.toolName !== "agent_contract_acknowledge_proposal" ||
    acknowledgmentRecord.argumentsDigest !== acknowledgmentObjectDigest ||
    acknowledgmentRecord.persistedObjectDigest !== acknowledgmentObjectDigest ||
    acknowledgmentRecord.messageDigest !== acknowledgmentMessageDigest ||
    acknowledgmentRecord.predecessorMessageDigest !== proposalMessageDigest ||
    acknowledgmentMessage?.metadata?.clockchainTrust?.predecessorMessageDigest !==
      proposalMessageDigest
  ) fail("Live runtime authorship binding invalid.");

  const eventInputs = [
    ["certificate_verified", new Date(evidence.monitor.checker.lastSeenMs).toISOString()],
    ["session_activated", strictIso(activationAt)],
    ["agent_card_discovered", strictIso(discovery.occurredAt)],
    ["proposal_authored", strictIso(proposalRecord.authoredAt)],
    ["proposal_persisted_verified", strictIso(proposalRecord.persistedAt)],
    ["acknowledgment_authored", strictIso(acknowledgmentRecord.authoredAt)],
    ["acknowledgment_persisted_verified", strictIso(acknowledgmentRecord.persistedAt)],
    ["witness_completed", strictIso(completedAt)],
  ];
  const startedAt = new Date(evidence.monitor.certificate.issuedAtMs).toISOString();
  let previous = Date.parse(startedAt);
  const events = eventInputs.map(([kind, occurredAt], index) => {
    const current = Date.parse(occurredAt);
    if (
      !Number.isFinite(current) ||
      (index === 0 && current < previous) ||
      (index > 0 && current <= previous)
    ) {
      fail("Live runtime witness event order invalid.");
    }
    previous = current;
    const event = Object.freeze({ sequence: index + 1, kind, occurredAt });
    return Object.freeze({ ...event, eventDigest: canonicalDigest(event) });
  });

  const result = Object.freeze({
    schema: "agent-contract.live-runtime-a2a-witness/v1",
    status: "completed",
    mode: "fresh_live_two_runtime",
    facilitator: "agent_contract_a2a",
    runId: evidence.runId,
    startedAt,
    completedAt: strictIso(completedAt),
    source,
    scenario: Object.freeze({
      source: "deterministic_input",
      digest: canonicalDigest(Object.freeze({
        opportunityId: "opportunity:1",
        reference: "NS-1847",
        scope: FACILITATED_A2A_SCOPE,
      })),
    }),
    runtimes: Object.freeze({
      buyer: Object.freeze({ role: "buyer", ...buyer.runtime }),
      provider: Object.freeze({ role: "provider", ...provider.runtime }),
    }),
    certificate: Object.freeze({
      provenance: "live_mcp",
      certificateDigest: `0x${evidence.binding.certificateDigest}`,
      continuationDigest: evidence.facilitatedA2AContinuationDigest,
      sessionId: evidence.monitor.sessionId,
    }),
    authorship: Object.freeze({
      proposal: Object.freeze({
        role: "provider",
        runtimeId: provider.runtime.runtimeId,
        toolName: proposalRecord.toolName,
        argumentsDigest: proposalRecord.argumentsDigest,
        persistedObjectDigest: proposalRecord.persistedObjectDigest,
        messageDigest: proposalRecord.messageDigest,
        predecessorMessageDigest: null,
        occurredAt: strictIso(proposalRecord.authoredAt),
      }),
      acknowledgment: Object.freeze({
        role: "buyer",
        runtimeId: buyer.runtime.runtimeId,
        toolName: acknowledgmentRecord.toolName,
        argumentsDigest: acknowledgmentRecord.argumentsDigest,
        persistedObjectDigest: acknowledgmentRecord.persistedObjectDigest,
        messageDigest: acknowledgmentRecord.messageDigest,
        predecessorMessageDigest: acknowledgmentRecord.predecessorMessageDigest,
        occurredAt: strictIso(acknowledgmentRecord.authoredAt),
      }),
    }),
    events: Object.freeze(events),
    acceptance: Object.freeze({
      distinctRuntimeProcessesVerified: true,
      certificateVerified: true,
      identityContinuityVerified: true,
      authorityVerified: true,
      proposalSignatureVerified: true,
      acknowledgmentSignatureVerified: true,
      authorshipBindingVerified: true,
      predecessorBindingVerified: true,
      eventOrderVerified: true,
    }),
    privacy: Object.freeze({
      rawTranscriptRetained: false,
      chainOfThoughtRetained: false,
      privateKeysRetained: false,
      capabilitiesRetained: false,
      bearerTokensRetained: false,
      secretScan: "PASS",
    }),
  });
  return result;
}

export async function runAgentContractA2AFlow({
  evidence,
  continueRole,
  baseUrl,
  operatorToken,
  fetchImpl = globalThis.fetch,
  now = () => new Date().toISOString(),
  witnessSource: rawWitnessSource,
} = {}) {
  if (typeof continueRole !== "function" || typeof fetchImpl !== "function" || typeof now !== "function" || typeof operatorToken !== "string" || operatorToken.length === 0) {
    fail("Agent Contract A2A flow dependencies invalid.");
  }
  const origin = loopbackBaseUrl(baseUrl);
  const validated = validateEvidence(evidence);
  const timestamp = strictIso(now());
  const certificate = handshakeEvidence(validated);
  if (Date.parse(timestamp) < Date.parse(certificate.issuedAt) || Date.parse(timestamp) > Date.parse(certificate.expiresAt)) {
    fail("Agent Contract A2A activation is outside the verified certificate window.");
  }
  const activated = activation(await requestJson(fetchImpl, `${origin}/api/agent-contract/harness/a2a/activate`, {
    method: "POST",
    token: operatorToken,
    body: { handshakeEvidence: certificate, evidenceClass: "live", now: timestamp },
  }), certificate.sessionId);

  const providerEnvironment = environment({
    baseUrl: origin,
    sessionId: activated.sessionId,
    certificateDigest: certificate.certificateDigest,
    continuationDigest: activated.authorization.digest,
    role: "provider",
    identity: validated.provider,
    partyId: "provider:proofworks",
    token: activated.capabilities.provider,
  });
  const providerContinuation = await continueRole("responder", { prompt: PROVIDER_PROMPT, environment: providerEnvironment });

  const buyerInbox = await requestJson(fetchImpl, `${origin}/api/a2a/sessions/${activated.sessionId}/agents/buyer/inbox`, {
    token: activated.capabilities.buyer,
  });
  const proposalTask = singleProposalTask(buyerInbox, activated.sessionId);

  const buyerEnvironment = environment({
    baseUrl: origin,
    sessionId: activated.sessionId,
    certificateDigest: certificate.certificateDigest,
    continuationDigest: activated.authorization.digest,
    role: "buyer",
    identity: validated.buyer,
    partyId: "buyer:co",
    token: activated.capabilities.buyer,
  });
  const buyerContinuation = await continueRole("initiator", { prompt: BUYER_PROMPT, environment: buyerEnvironment });

  const exported = await requestJson(fetchImpl, `${origin}/api/agent-contract/harness/a2a/export`, {
    method: "POST",
    token: operatorToken,
    body: { sessionId: activated.sessionId },
  });
  const verified = validateExport(exported, validated, proposalTask.id, activated.authorization.digest);
  const liveRuntimeWitness = rawWitnessSource === undefined
    ? undefined
    : buildLiveRuntimeWitness({
        completedAt: strictIso(now()),
        evidence: Object.freeze({
          ...evidence,
          facilitatedA2AContinuationDigest: activated.authorization.digest,
        }),
        source: witnessSource(rawWitnessSource),
        activationAt: timestamp,
        providerContinuation,
        buyerContinuation,
        verified,
      });
  const result = Object.freeze({
    schema: RESULT_SCHEMA,
    provenance: "live_a2a_facilitator",
    sessionId: activated.sessionId,
    clients: Object.freeze({ buyer: "codex", provider: "claude" }),
    identities: Object.freeze({
      buyer: Object.freeze({ address: validated.buyer.address, erc8004AgentId: validated.buyer.erc8004.agentId }),
      provider: Object.freeze({ address: validated.provider.address, erc8004AgentId: validated.provider.erc8004.agentId }),
    }),
    certificateDigest: certificate.certificateDigest,
    continuationDigest: activated.authorization.digest,
    proposalTaskId: proposalTask.id,
    acknowledgmentTaskId: verified.acknowledgmentTaskId,
    verification: verified.verification,
    ...(liveRuntimeWitness === undefined ? {} : { liveRuntimeWitness }),
  });
  assertSecretFree(result, [operatorToken, activated.capabilities.buyer, activated.capabilities.provider]);
  return result;
}
