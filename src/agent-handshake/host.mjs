import {
  AGENT_HANDSHAKE_CHAIN_ID,
  AGENT_HANDSHAKE_DESCRIPTOR_SCHEMA,
  AGENT_HANDSHAKE_REGISTRY_ADDRESS,
  createAgentDescriptorEnvelope,
} from "./descriptor.mjs";
import { buildAgentHandshakeResult } from "./result.mjs";
import {
  verifyAgentHandshakeAcceptance,
  verifyAgentHandshakeProposal,
} from "./statement.mjs";
import { verifyAgentHandshakeAuthorization } from "./verdict.mjs";
import { buildAgentHandshakeSnapshot } from "../monitor/agent-snapshot.mjs";

export const AGENT_HANDSHAKE_HOST_ROLES = Object.freeze({
  roles: ["initiator", "responder"],
}.roles);

function identity(party) {
  return Object.freeze({
    address: party.address,
    agentId: party.agentId,
    chainId: AGENT_HANDSHAKE_CHAIN_ID,
    reference: `eip155:${AGENT_HANDSHAKE_CHAIN_ID}:${AGENT_HANDSHAKE_REGISTRY_ADDRESS}:${party.agentId}`,
    registryAddress: AGENT_HANDSHAKE_REGISTRY_ADDRESS,
  });
}

function requirePorts(ports) {
  for (const name of [
    "announceParties",
    "awaitAcceptance",
    "awaitAnchors",
    "awaitEvidence",
    "awaitIdentity",
    "awaitPartyReady",
    "awaitProposal",
    "fundIdentity",
    "publishDescriptor",
    "publishResult",
    "publishSnapshot",
    "resolveOwner",
  ]) {
    if (typeof ports?.[name] !== "function") throw new TypeError("Invalid agent handshake host port.");
  }
}

export async function runAgentHandshakeHostSession({ now = Date.now, ports, session }) {
  requirePorts(ports);
  const state = {
    anchors: { acceptance: null, acknowledgment: null, proposal: null },
    funding: null,
    heartbeat: { checker: null, initiator: null, responder: null },
    identities: null,
    stageHistory: [],
    verdict: null,
  };
  const publish = async (currentStage) => {
    const atMs = now();
    state.stageHistory = [...state.stageHistory, { atMs, status: currentStage }];
    await ports.publishSnapshot(buildAgentHandshakeSnapshot({
      ...state,
      currentStage,
      reasonCode: null,
      reference: session.terms.reference,
      sessionId: session.sessionId,
      statement: session.terms.statement,
      subjectRun: "stakeholder",
      updatedAtMs: atMs,
    }));
  };

  await publish("SESSION_STARTED");
  const claims = {};
  for (const role of AGENT_HANDSHAKE_HOST_ROLES) {
    claims[role] = await ports.awaitIdentity(role);
    await ports.fundIdentity({ address: claims[role].address, role });
    state.heartbeat[role] = { lastSeenMs: now() };
  }
  state.funding = { atMs: now(), funded: true };
  const parties = {};
  for (const role of AGENT_HANDSHAKE_HOST_ROLES) {
    parties[role] = await ports.awaitPartyReady(role);
    if (parties[role].address !== claims[role].address) {
      throw new Error("Agent identity changed after registration funding.");
    }
  }
  state.identities = {
    initiator: identity(parties.initiator),
    responder: identity(parties.responder),
  };
  await ports.announceParties(parties);
  await publish("IDENTITIES_REGISTERED");

  const proposalEnvelope = await ports.awaitProposal();
  await verifyAgentHandshakeProposal({
    envelope: proposalEnvelope,
    expectedRepositorySha: session.repositorySha,
    expectedSessionId: session.sessionId,
    expectedTerms: session.terms,
    nowMs: now(),
  });
  await publish("STATEMENT_PROPOSED");
  const acceptanceEnvelope = await ports.awaitAcceptance();
  await verifyAgentHandshakeAcceptance({
    envelope: acceptanceEnvelope,
    expectedRepositorySha: session.repositorySha,
    expectedSessionId: session.sessionId,
    expectedTerms: session.terms,
    nowMs: now(),
    proposalEnvelope,
  });
  await publish("STATEMENT_ACCEPTED");

  const proposal = proposalEnvelope.proposal;
  const descriptorEnvelope = createAgentDescriptorEnvelope({
    chainId: AGENT_HANDSHAKE_CHAIN_ID,
    expiresAtMs: proposal.expiresAtMs,
    externalActionPerformed: false,
    initiator: proposal.initiator,
    operatorPublicKey: session.expectedPublicKey,
    protocol: proposal.protocol,
    reference: proposal.reference,
    registryAddress: AGENT_HANDSHAKE_REGISTRY_ADDRESS,
    repositorySha: proposal.repositorySha,
    responder: proposal.responder,
    schema: AGENT_HANDSHAKE_DESCRIPTOR_SCHEMA,
    sessionId: proposal.sessionId,
    statementDigest: proposal.statementDigest,
  }, { keyId: session.keyId, privateKeyPem: session.privateKeyPem });
  await ports.publishDescriptor(descriptorEnvelope);

  const anchorReport = await ports.awaitAnchors(descriptorEnvelope);
  for (const [index, stage] of ["PROPOSED", "ACCEPTED", "ACKNOWLEDGED"].entries()) {
    const transition = anchorReport.transitions[index];
    const receipt = anchorReport.receipts[index];
    const kind = ["proposal", "acceptance", "acknowledgment"][index];
    state.anchors[kind] = {
      actor: ["initiator", "responder", "clockchain"][index],
      blockHeight: receipt.blockHeight,
      blockTime: Date.parse(receipt.blockTimeRaw),
      explorerUrl: `https://clockchain.network/ledger/${receipt.ledgerId}`,
      kind,
      ledgerId: receipt.ledgerId,
      receipt: { digest: receipt.digest },
      terms: {
        expiresAtMs: transition.expiresAtMs,
        predecessor: transition.predecessor,
        reference: transition.reference,
        sequence: transition.sequence,
        sessionDigest: transition.sessionDigest,
        statementDigest: transition.statementDigest,
      },
    };
    await publish(stage);
  }

  const evidence = {
    initiator: await ports.awaitEvidence("initiator"),
    responder: await ports.awaitEvidence("responder"),
  };
  await publish("EVIDENCE_RECEIVED");
  state.heartbeat.checker = { lastSeenMs: now() };
  await publish("VERIFYING");
  const verdict = await verifyAgentHandshakeAuthorization({
    acceptanceEnvelope,
    descriptorEnvelope,
    evidence,
    expectedPublicKey: session.expectedPublicKey,
    expectedRepositorySha: session.repositorySha,
    expectedSessionId: session.sessionId,
    expectedTerms: session.terms,
    nowMs: now(),
    proposalEnvelope,
    receipts: anchorReport.receipts,
    resolveOwner: ports.resolveOwner,
    transitions: anchorReport.transitions,
  });
  const certificate = buildAgentHandshakeResult({
    issuedAtMs: String(now()),
    keyId: session.keyId,
    parties,
    privateKeyPem: session.privateKeyPem,
    sessionId: session.sessionId,
    verdict,
  });
  await ports.publishResult(certificate);
  state.verdict = {
    externalActionPerformed: false,
    outcome: verdict.outcome,
    reference: verdict.reference,
    sessionDigest: verdict.sessionDigest,
    statementDigest: verdict.statementDigest,
  };
  await publish("CERTIFIED");
  return Object.freeze({ certificate, descriptorEnvelope, verdict });
}
