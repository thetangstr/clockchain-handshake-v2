import { generateKeyPairSync } from "node:crypto";

import { privateKeyToAccount } from "viem/accounts";

import {
  agentDescriptorDigest,
  createAgentDescriptorEnvelope,
  rawAgentOperatorPublicKey,
} from "../../src/agent-handshake/descriptor.mjs";
import {
  agentTransitionDigest,
  createAgentAcceptance,
  createAgentAcknowledgment,
  createAgentProposal,
} from "../../src/agent-handshake/protocol.mjs";
import {
  AGENT_HANDSHAKE_ACCEPTANCE_SCHEMA,
  AGENT_HANDSHAKE_PROPOSAL_SCHEMA,
  agentHandshakeProposalDigest,
  agentHandshakeStatementDigest,
  signAgentHandshakeAcceptance,
  signAgentHandshakeProposal,
} from "../../src/agent-handshake/statement.mjs";

export const INITIATOR = privateKeyToAccount(`0x${"4".repeat(64)}`);
export const RESPONDER = privateKeyToAccount(`0x${"5".repeat(64)}`);
export const SESSION_ID = "22222222-3333-4444-8555-666666666666";
export const REPOSITORY_SHA = "d".repeat(40);
export const TERMS = Object.freeze({
  reference: "NS-1847",
  statement: "Northstar Logistics and Harbor Supply confirm that these two registered agents are authorized to communicate about shipment reference NS-1847 for the next 45 minutes.",
  validForMinutes: "45",
});
export const ISSUED_AT_MS = "1786337100000";
export const EXPIRES_AT_MS = "1786339800000";
export const NOW_MS = 1786337160000;

export function createHost(keyId = "generic-host-1") {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" });
  return Object.freeze({
    keyId,
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
    publicKey: rawAgentOperatorPublicKey(publicKeyPem),
  });
}

export async function buildAgentHandshakeFixture(host = createHost()) {
  const initiator = Object.freeze({
    address: INITIATOR.address.toLowerCase(),
    agentId: "9452",
  });
  const responder = Object.freeze({
    address: RESPONDER.address.toLowerCase(),
    agentId: "9453",
  });
  const proposalEnvelope = await signAgentHandshakeProposal({
    proposal: {
      expiresAtMs: EXPIRES_AT_MS,
      externalActionPerformed: false,
      initiator,
      issuedAtMs: ISSUED_AT_MS,
      protocol: "clockchain.agent-handshake/v1",
      reference: TERMS.reference,
      repositorySha: REPOSITORY_SHA,
      responder,
      schema: AGENT_HANDSHAKE_PROPOSAL_SCHEMA,
      sessionId: SESSION_ID,
      statement: TERMS.statement,
      statementDigest: agentHandshakeStatementDigest(TERMS),
      subjectRun: "stakeholder",
      validForMinutes: TERMS.validForMinutes,
    },
    signMessage: (bytes) => INITIATOR.signMessage({ message: { raw: bytes } }),
  });
  const acceptanceEnvelope = await signAgentHandshakeAcceptance({
    acceptance: {
      decision: "ACCEPTED",
      expiresAtMs: EXPIRES_AT_MS,
      externalActionPerformed: false,
      initiator,
      issuedAtMs: "1786337160000",
      proposalDigest: agentHandshakeProposalDigest(proposalEnvelope),
      protocol: "clockchain.agent-handshake/v1",
      reference: TERMS.reference,
      repositorySha: REPOSITORY_SHA,
      responder,
      schema: AGENT_HANDSHAKE_ACCEPTANCE_SCHEMA,
      sessionId: SESSION_ID,
      statementDigest: agentHandshakeStatementDigest(TERMS),
      subjectRun: "stakeholder",
    },
    proposalEnvelope,
    signMessage: (bytes) => RESPONDER.signMessage({ message: { raw: bytes } }),
  });
  const descriptorEnvelope = createAgentDescriptorEnvelope({
    chainId: "11155111",
    expiresAtMs: EXPIRES_AT_MS,
    externalActionPerformed: false,
    initiator,
    operatorPublicKey: host.publicKey,
    protocol: "clockchain.agent-handshake/v1",
    reference: TERMS.reference,
    registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha: REPOSITORY_SHA,
    responder,
    schema: "clockchain.agent-handshake-descriptor/v1",
    sessionId: SESSION_ID,
    statementDigest: agentHandshakeStatementDigest(TERMS),
  }, { keyId: host.keyId, privateKeyPem: host.privateKeyPem });
  const base = {
    expiresAtMs: EXPIRES_AT_MS,
    initiator,
    reference: TERMS.reference,
    responder,
    sessionDigest: agentDescriptorDigest(descriptorEnvelope.descriptor),
    statementDigest: agentHandshakeStatementDigest(TERMS),
  };
  const proposed = createAgentProposal(base);
  const accepted = createAgentAcceptance({
    ...base,
    predecessor: agentTransitionDigest(proposed),
  }, proposed);
  const acknowledged = createAgentAcknowledgment({
    ...base,
    predecessor: agentTransitionDigest(accepted),
  }, accepted);
  const transitions = Object.freeze([proposed, accepted, acknowledged]);
  const receipts = Object.freeze(transitions.map((transition, index) => Object.freeze({
    blockHeight: String(7000 + index),
    blockTimeRaw: `2026-08-09T17:0${index}:00.000Z`,
    digest: agentTransitionDigest(transition),
    kind: ["proposal", "acceptance", "acknowledgment"][index],
    ledgerId: [
      "33333333-4444-4555-8666-777777777770",
      "33333333-4444-4555-8666-777777777771",
      "33333333-4444-4555-8666-777777777772",
    ][index],
  })));
  return Object.freeze({
    acceptanceEnvelope,
    base,
    descriptorEnvelope,
    host,
    initiator,
    proposalEnvelope,
    receipts,
    responder,
    transitions,
  });
}
