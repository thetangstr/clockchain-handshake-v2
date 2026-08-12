import { validateAgentHandshakeV2Party } from "./party.mjs";
import { validateIdentityPolicy } from "./terms.mjs";
import {
  verifyAgentHandshakeV2Acceptance,
  verifyAgentHandshakeV2Proposal,
} from "./protocol.mjs";
import {
  createAgentHandshakeV2DescriptorEnvelope,
} from "./descriptor.mjs";
import { hostSessionKeyCertificateDigest } from "./host-key-certificate.mjs";
import { verifyAgentHandshakeV2Authorization } from "./verdict.mjs";
import { buildAgentHandshakeV2Result } from "./result.mjs";

export const AGENT_HANDSHAKE_V2_HOST_ROLES = Object.freeze([
  "initiator",
  "responder",
]);

export class AgentHandshakeV2HostError extends Error {
  constructor() {
    super("Agent handshake v2 host stopped.");
    this.name = "AgentHandshakeV2HostError";
    this.category = "verification";
    this.code = "AGENT_HANDSHAKE_V2_HOST_INVALID";
  }
}

function invalid() {
  throw new AgentHandshakeV2HostError();
}

function requirePorts(ports) {
  for (const name of ["awaitIdentityClaim", "awaitPartyReady"]) {
    if (typeof ports?.[name] !== "function") invalid();
  }
}

function claim(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 2 ||
    !/^0x[0-9a-f]{40}$/.test(value.sessionKeyAddress) ||
    !/^[0-9a-f]{64}$/.test(value.policyDigest)
  ) invalid();
  return Object.freeze({
    policyDigest: value.policyDigest,
    sessionKeyAddress: value.sessionKeyAddress,
  });
}

export async function prepareAgentHandshakeV2Identities({
  identityPolicy: rawPolicy,
  ports,
  sessionId,
  sessionOpenedBlock,
}) {
  requirePorts(ports);
  let identityPolicy;
  try { identityPolicy = validateIdentityPolicy(rawPolicy); } catch { invalid(); }
  if (
    typeof sessionId !== "string" ||
    !/^[0-9a-f-]{36}$/.test(sessionId) ||
    typeof sessionOpenedBlock !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/.test(sessionOpenedBlock)
  ) invalid();
  const claims = {};
  for (const role of AGENT_HANDSHAKE_V2_HOST_ROLES) {
    claims[role] = claim(await ports.awaitIdentityClaim(role));
  }
  if (claims.initiator.sessionKeyAddress === claims.responder.sessionKeyAddress) invalid();

  const addressesToFund = [];
  if (identityPolicy.erc8004 === "required_fresh") {
    addressesToFund.push(
      claims.initiator.sessionKeyAddress,
      claims.responder.sessionKeyAddress,
    );
  } else if (identityPolicy.erc8004 === "required_existing_or_fresh") {
    if (typeof ports.findExistingIdentity !== "function") invalid();
    for (const role of AGENT_HANDSHAKE_V2_HOST_ROLES) {
      const existing = await ports.findExistingIdentity(claims[role].sessionKeyAddress);
      if (existing === null) addressesToFund.push(claims[role].sessionKeyAddress);
    }
  }
  if (addressesToFund.length > 0) {
    if (
      typeof ports.reserveFunding !== "function" ||
      typeof ports.fundIdentity !== "function"
    ) invalid();
    await ports.reserveFunding({
      addresses: addressesToFund,
      identityMode: identityPolicy.erc8004,
      sessionId,
    });
    for (const role of AGENT_HANDSHAKE_V2_HOST_ROLES) {
      if (addressesToFund.includes(claims[role].sessionKeyAddress)) {
        await ports.fundIdentity({
          address: claims[role].sessionKeyAddress,
          role,
        });
      }
    }
  }

  const parties = {};
  for (const role of AGENT_HANDSHAKE_V2_HOST_ROLES) {
    try {
      parties[role] = validateAgentHandshakeV2Party(
        await ports.awaitPartyReady(role),
        { identityPolicy },
      );
    } catch {
      invalid();
    }
    if (
      parties[role].sessionKeyAddress !== claims[role].sessionKeyAddress ||
      parties[role].policyDigest !== claims[role].policyDigest
    ) invalid();
  }
  if (
    parties.initiator.sessionKeyAddress === parties.responder.sessionKeyAddress ||
    parties.initiator.policyDigest === parties.responder.policyDigest
  ) invalid();
  if (identityPolicy.erc8004 !== "not_required") {
    if (
      parties.initiator.erc8004.agentId === parties.responder.erc8004.agentId ||
      typeof ports.resolveRegistration !== "function"
    ) invalid();
    for (const role of AGENT_HANDSHAKE_V2_HOST_ROLES) {
      const resolved = await ports.resolveRegistration(parties[role]);
      if (
        resolved?.owner !== parties[role].sessionKeyAddress ||
        resolved.registrationBlock !== parties[role].erc8004.registrationBlock ||
        (
          identityPolicy.erc8004 === "required_fresh" &&
          BigInt(resolved.registrationBlock) <= BigInt(sessionOpenedBlock)
        )
      ) invalid();
    }
  }
  return Object.freeze({
    initiator: parties.initiator,
    responder: parties.responder,
  });
}

function requireSessionPorts(ports) {
  for (const name of [
    "acceptanceSigned",
    "anchorsRecorded",
    "awaitAcceptance",
    "awaitAnchors",
    "awaitCommitmentCheckpoint",
    "awaitEvidence",
    "awaitInvitationClaimed",
    "awaitProposal",
    "certificateIssued",
    "checkerStage",
    "evidenceReceived",
    "failed",
    "partiesReady",
    "proposalSigned",
    "publishInitial",
    "publishDescriptor",
    "publishResult",
  ]) {
    if (typeof ports?.[name] !== "function") invalid();
  }
}

export async function runAgentHandshakeV2HostSession({
  now = Date.now,
  ports,
  session,
}) {
  requirePorts(ports);
  requireSessionPorts(ports);
  if (
    session?.protocol !== "clockchain.agent-handshake/v2" ||
    !Number.isSafeInteger(session.sessionOpenedAtMs) ||
    !Number.isSafeInteger(session.sessionDeadlineMs) ||
    session.sessionDeadlineMs !== session.sessionOpenedAtMs + 10 * 60_000 ||
    now() >= session.sessionDeadlineMs
  ) invalid();
  await ports.publishInitial();
  await ports.awaitInvitationClaimed();
  const parties = await prepareAgentHandshakeV2Identities({
    identityPolicy: session.terms.identityPolicy,
    ports,
    sessionId: session.sessionId,
    sessionOpenedBlock: session.sessionOpenedBlock,
  });
  await ports.partiesReady(parties);
  const proposalEnvelope = await ports.awaitProposal();
  const proposal = await verifyAgentHandshakeV2Proposal({
    envelope: proposalEnvelope,
    expectedRepositorySha: session.repositorySha,
    expectedSessionId: session.sessionId,
    expectedTerms: session.terms,
    nowMs: now(),
  });
  await ports.proposalSigned(proposalEnvelope);
  const acceptanceEnvelope = await ports.awaitAcceptance();
  await verifyAgentHandshakeV2Acceptance({
    envelope: acceptanceEnvelope,
    expectedRepositorySha: session.repositorySha,
    expectedSessionId: session.sessionId,
    expectedTerms: session.terms,
    nowMs: now(),
    proposalEnvelope,
  });
  await ports.acceptanceSigned(acceptanceEnvelope);
  const commitmentCheckpoints = [
    await ports.awaitCommitmentCheckpoint("initiator"),
    await ports.awaitCommitmentCheckpoint("responder"),
  ];
  const descriptorEnvelope = createAgentHandshakeV2DescriptorEnvelope({
    agreementExpiresAtMs: proposal.payload.expiresAtMs,
    externalBusinessActionPerformed: false,
    hostSessionKeyCertificateDigest:
      hostSessionKeyCertificateDigest(session.hostSessionKeyCertificate),
    identityPolicy: session.terms.identityPolicy,
    initiator: parties.initiator,
    operatorPublicKey: session.expectedPublicKey,
    protocol: session.protocol,
    reference: session.terms.reference,
    repositorySha: session.repositorySha,
    responder: parties.responder,
    schema: "clockchain.agent-handshake-descriptor/v2",
    sessionId: session.sessionId,
    sessionOpenedAtMs: String(session.sessionOpenedAtMs),
    sessionOpenedBlock: session.sessionOpenedBlock,
    statementDigest: proposal.payload.statementDigest,
  }, { keyId: session.keyId, privateKeyPem: session.privateKeyPem });
  await ports.publishDescriptor(descriptorEnvelope);
  const anchorReport = await ports.awaitAnchors(descriptorEnvelope);
  await ports.anchorsRecorded(anchorReport);
  const evidence = {};
  evidence.initiator = await ports.awaitEvidence("initiator");
  await ports.evidenceReceived("initiator", evidence.initiator);
  evidence.responder = await ports.awaitEvidence("responder");
  await ports.evidenceReceived("responder", evidence.responder);
  await ports.checkerStage("VERIFYING");
  let verdict;
  try {
    verdict = await verifyAgentHandshakeV2Authorization({
      commitmentCheckpoints,
      acceptanceEnvelope,
      descriptorEnvelope,
      evidence,
      expectedHostSessionKeyCertificateDigest:
        descriptorEnvelope.descriptor.hostSessionKeyCertificateDigest,
      expectedPublicKey: session.expectedPublicKey,
      expectedRepositorySha: session.repositorySha,
      expectedSessionId: session.sessionId,
      expectedTerms: session.terms,
      nowMs: now(),
      proposalEnvelope,
      receipts: anchorReport.receipts,
      requireCommitmentCheckpoints: true,
      resolveRegistration: ports.resolveRegistration,
      transitions: anchorReport.transitions,
    });
  } catch (error) {
    await ports.failed(error?.code ?? "AGENT_HANDSHAKE_V2_VERDICT_INVALID");
    throw error;
  }
  const certificate = buildAgentHandshakeV2Result({
    hostSessionKeyCertificate: session.hostSessionKeyCertificate,
    issuedAtMs: String(now()),
    keyId: session.keyId,
    parties,
    privateKeyPem: session.privateKeyPem,
    sessionId: session.sessionId,
    verdict,
  });
  await ports.publishResult(certificate);
  await ports.certificateIssued(certificate);
  return Object.freeze({
    certificate,
    descriptorEnvelope,
    verdict,
  });
}
