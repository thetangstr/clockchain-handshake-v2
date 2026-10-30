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
import { monotonicClock } from "./clock.mjs";

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

// H-REQ-07: the agreement, the host session key or the session itself lapsed
// while the host was verifying. Reported through the session's failure path.
export class AgentHandshakeV2SigningWindowExpired extends Error {
  constructor() {
    super("Agent handshake v2 signing window expired.");
    this.name = "AgentHandshakeV2SigningWindowExpired";
    this.category = "verification";
    this.code = "AGENT_HANDSHAKE_V2_SIGNING_WINDOW_EXPIRED";
  }
}

// Publish the lapse on the snapshot and to both parties, as the verdict
// failure path does, then stop.
async function signingWindowExpired(ports) {
  const error = new AgentHandshakeV2SigningWindowExpired();
  await ports.failed(error.code);
  await notifySessionFailed(ports, error.code);
  throw error;
}

function certificateWindow(hostSessionKeyCertificate) {
  const validFromMs = Number(hostSessionKeyCertificate?.certificate?.validFromMs);
  const validUntilMs = Number(hostSessionKeyCertificate?.certificate?.validUntilMs);
  if (
    !Number.isSafeInteger(validFromMs) ||
    !Number.isSafeInteger(validUntilMs) ||
    validFromMs >= validUntilMs
  ) invalid();
  return Object.freeze({ validFromMs, validUntilMs });
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
      const resolved = await ports.resolveRegistration(parties[role].erc8004.agentId, {
        expectedOwner: parties[role].sessionKeyAddress,
        registrationBlock: parties[role].erc8004.registrationBlock,
      });
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

// Tell both parties on the relay log that this session has ended. Optional
// port (older adapters lack it) and best effort: the snapshot carries the same
// failure.
async function notifySessionFailed(ports, code) {
  if (typeof ports.notifySessionFailed !== "function") return;
  try {
    await ports.notifySessionFailed(code);
  } catch {}
}

async function publishPreparationFailure(ports, code) {
  try {
    await ports.failed(code);
  } catch {}
  await notifySessionFailed(ports, code);
}

// Claim-stage failures that end the session with an explicit terminal state.
const CLAIM_TERMINAL_CODES = new Set([
  "AGENT_HANDSHAKE_V2_INVITATION_EXPIRED",
  // H-REQ-01: the coordinator's sender enrollments disagree with each other or
  // with the invitation messages.
  "AGENT_HANDSHAKE_V2_RELAY_BINDING_INVALID",
]);

// A snapshot rejection is published and notified by the port itself; the
// runner must not overwrite that terminal state under a different code.
function alreadyPublished(error) {
  return error?.name === "AgentHandshakeV2SessionFailure" && error.published === true;
}

export async function runAgentHandshakeV2HostSession({
  now = Date.now,
  ports,
  session,
}) {
  requirePorts(ports);
  requireSessionPorts(ports);
  // Every freshness decision reads this clock again; a read that goes
  // backwards or is not a safe integer fails closed.
  let clock;
  try { clock = monotonicClock(now); } catch { invalid(); }
  const read = () => {
    try { return clock.read(); } catch { return invalid(); }
  };
  if (
    session?.protocol !== "clockchain.agent-handshake/v2" ||
    !Number.isSafeInteger(session.sessionOpenedAtMs) ||
    !Number.isSafeInteger(session.invitationExpiresAtMs) ||
    !Number.isSafeInteger(session.sessionDeadlineMs) ||
    session.invitationExpiresAtMs !== session.sessionOpenedAtMs + 120_000 ||
    session.sessionDeadlineMs !== session.sessionOpenedAtMs + 10 * 60_000 ||
    read() >= session.sessionDeadlineMs
  ) invalid();
  // H-REQ-07: every signing, publishing or admission step that follows an
  // await reads the clock again first. The session deadline and the end of the
  // host key's validity bound every step; once the proposal is verified, its
  // agreement expiry bounds them too. A lapse ends the session through its
  // failure path.
  const { validFromMs, validUntilMs } = certificateWindow(session.hostSessionKeyCertificate);
  let agreementExpiresAtMs = null;
  const lapsed = (atMs) =>
    atMs >= session.sessionDeadlineMs ||
    atMs >= validUntilMs ||
    (agreementExpiresAtMs !== null && atMs >= agreementExpiresAtMs);
  const fresh = async () => {
    const atMs = read();
    if (lapsed(atMs)) await signingWindowExpired(ports);
    return atMs;
  };
  await ports.publishInitial();
  try {
    await ports.awaitInvitationClaimed();
  } catch (error) {
    if (!alreadyPublished(error) && CLAIM_TERMINAL_CODES.has(error?.code)) {
      await publishPreparationFailure(ports, error.code);
    }
    throw error;
  }
  let fundingPreparationError = undefined;
  let sawFundingPreparationError = false;
  const preparationPorts = { ...ports };
  if (typeof ports.fundIdentity === "function") {
    preparationPorts.fundIdentity = async (...args) => {
      await fresh();
      try {
        return await ports.fundIdentity(...args);
      } catch (error) {
        sawFundingPreparationError = true;
        fundingPreparationError = error;
        throw error;
      }
    };
  }
  if (typeof ports.reserveFunding === "function") {
    preparationPorts.reserveFunding = async (...args) => {
      await fresh();
      try {
        return await ports.reserveFunding(...args);
      } catch (error) {
        sawFundingPreparationError = true;
        fundingPreparationError = error;
        throw error;
      }
    };
  }
  let parties;
  try {
    parties = await prepareAgentHandshakeV2Identities({
      identityPolicy: session.terms.identityPolicy,
      ports: preparationPorts,
      sessionId: session.sessionId,
      sessionOpenedBlock: session.sessionOpenedBlock,
    });
  } catch (error) {
    if (alreadyPublished(error) || error instanceof AgentHandshakeV2SigningWindowExpired) throw error;
    await publishPreparationFailure(
      ports,
      sawFundingPreparationError && Object.is(error, fundingPreparationError)
        ? "AGENT_HANDSHAKE_V2_FUNDING_UNAVAILABLE"
        : "AGENT_HANDSHAKE_V2_IDENTITY_PREPARATION_FAILED",
    );
    throw error;
  }
  await fresh();
  await ports.partiesReady(parties);
  const proposalEnvelope = await ports.awaitProposal();
  const proposal = await verifyAgentHandshakeV2Proposal({
    envelope: proposalEnvelope,
    expectedRepositorySha: session.repositorySha,
    expectedSessionId: session.sessionId,
    expectedTerms: session.terms,
    nowMs: read(),
  });
  agreementExpiresAtMs = Number(proposal.payload.expiresAtMs);
  await fresh();
  await ports.proposalSigned(proposalEnvelope);
  const acceptanceEnvelope = await ports.awaitAcceptance();
  await verifyAgentHandshakeV2Acceptance({
    envelope: acceptanceEnvelope,
    expectedRepositorySha: session.repositorySha,
    expectedSessionId: session.sessionId,
    expectedTerms: session.terms,
    nowMs: read(),
    proposalEnvelope,
  });
  await fresh();
  await ports.acceptanceSigned(acceptanceEnvelope);
  await fresh();
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
  await fresh();
  await ports.publishDescriptor(descriptorEnvelope);
  const anchorReport = await ports.awaitAnchors(descriptorEnvelope);
  await fresh();
  await ports.anchorsRecorded(anchorReport);
  const evidence = {};
  for (const role of AGENT_HANDSHAKE_V2_HOST_ROLES) {
    evidence[role] = await ports.awaitEvidence(role);
    await fresh();
    await ports.evidenceReceived(role, evidence[role]);
  }
  await fresh();
  await ports.checkerStage("VERIFYING");
  const verdictNowMs = await fresh();
  let verdict;
  try {
    verdict = await verifyAgentHandshakeV2Authorization({
      acceptanceEnvelope,
      descriptorEnvelope,
      evidence,
      expectedHostSessionKeyCertificateDigest:
        descriptorEnvelope.descriptor.hostSessionKeyCertificateDigest,
      expectedPublicKey: session.expectedPublicKey,
      expectedRepositorySha: session.repositorySha,
      expectedSessionId: session.sessionId,
      expectedTerms: session.terms,
      nowMs: verdictNowMs,
      proposalEnvelope,
      receipts: anchorReport.receipts,
      resolveRegistration: ports.resolveRegistration,
      transitions: anchorReport.transitions,
    });
  } catch (error) {
    if (alreadyPublished(error)) throw error;
    const code = error?.code ?? "AGENT_HANDSHAKE_V2_VERDICT_INVALID";
    await ports.failed(code);
    await notifySessionFailed(ports, code);
    throw error;
  }
  // The verdict awaited registration lookups and evidence checks: the clock is
  // read when it returns, and the certificate is issued at a read no earlier
  // than that, inside the agreement, the host key's validity and the session.
  const verificationCompletedAtMs = read();
  const issuedAtMs = read();
  if (issuedAtMs < validFromMs) invalid();
  if (lapsed(issuedAtMs)) await signingWindowExpired(ports);
  const certificate = buildAgentHandshakeV2Result({
    hostSessionKeyCertificate: session.hostSessionKeyCertificate,
    issuedAtMs: String(issuedAtMs),
    keyId: session.keyId,
    parties,
    privateKeyPem: session.privateKeyPem,
    sessionId: session.sessionId,
    verdict,
    verificationCompletedAtMs: String(verificationCompletedAtMs),
  });
  await fresh();
  // The publication port stops at the session deadline or the end of the host
  // key's validity, whichever comes first; once it returns, the result was
  // published inside that bound and is recorded as issued.
  await ports.publishResult(certificate);
  await ports.certificateIssued(certificate);
  return Object.freeze({
    certificate,
    descriptorEnvelope,
    verdict,
  });
}
