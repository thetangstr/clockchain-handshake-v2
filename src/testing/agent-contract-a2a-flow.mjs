import { assertSecretFree } from "../core/redact.mjs";

const RESULT_SCHEMA = "agent-contract.facilitated-a2a-result/v1";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const INTEGER = /^(?:0|[1-9][0-9]*)$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1", "localhost"]);
export const FACILITATED_A2A_SCOPE = "single_provider_proposal_nonbinding_buyer_acknowledgment";
export const FACILITATED_A2A_VALID_FOR_SECONDS = "600";
export const FACILITATED_A2A_AUTHORIZATION_STATEMENT = "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to establish one Agent Contract facilitated proposal session about shipment reference NS-1847. The session must be activated within 90 seconds and may remain active for up to 10 minutes. It permits one provider proposal and one nonbinding buyer acknowledgment; it does not authorize agreement, payment, escrow, execution, or any external business action.";
const VERIFICATION_KEYS = Object.freeze([
  "identityContinuity",
  "providerDiscoveredBuyerCard",
  "proposalSignatureVerified",
  "proposalAuthorityVerified",
  "buyerAcknowledgmentVerified",
  "predecessorBindingVerified",
]);

const PROVIDER_PROMPT = `The Clockchain handshake is already verified. Continue as the provider through the configured Agent Contract A2A tools. First discover the buyer Agent Card. Then independently choose the exact commercial terms for one small, real deliverable: a signed JSON and Markdown evidence pack that can be verified by checksum and required sections. Stay within your authority and call the proposal tool yourself. Do not claim negotiation, agreement, payment, escrow, or external execution.`;

const BUYER_PROMPT = `The Clockchain handshake is already verified. Continue as the buyer through the configured Agent Contract A2A tools. Read your authenticated inbox and evaluate the exact stored proposal. If it is the expected single small-deliverable proposal, acknowledge only that it was received for review. The acknowledgment must remain nonbinding. Do not accept terms, create an agreement, authorize payment, or claim escrow or execution.`;

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
  return value;
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
  return Object.freeze({ verification: Object.freeze(Object.fromEntries(VERIFICATION_KEYS.map((key) => [key, true]))), acknowledgmentTaskId: acknowledgments[0].id });
}

export async function runAgentContractA2AFlow({
  evidence,
  continueRole,
  baseUrl,
  operatorToken,
  fetchImpl = globalThis.fetch,
  now = () => new Date().toISOString(),
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
  await continueRole("responder", { prompt: PROVIDER_PROMPT, environment: providerEnvironment });

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
  await continueRole("initiator", { prompt: BUYER_PROMPT, environment: buyerEnvironment });

  const exported = await requestJson(fetchImpl, `${origin}/api/agent-contract/harness/a2a/export`, {
    method: "POST",
    token: operatorToken,
    body: { sessionId: activated.sessionId },
  });
  const verified = validateExport(exported, validated, proposalTask.id, activated.authorization.digest);
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
  });
  assertSecretFree(result, [operatorToken, activated.capabilities.buyer, activated.capabilities.provider]);
  return result;
}
