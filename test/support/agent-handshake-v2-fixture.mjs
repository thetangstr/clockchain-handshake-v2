import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";

import { agentHandshakeV2StatementDigest } from "../../src/agent-handshake/v2/terms.mjs";
import { localPolicyDigest } from "../../src/agent-handshake/v2/policy.mjs";
import {
  agentHandshakeV2ProposalDigest,
  agentHandshakeV2TransitionDigest,
  createAgentHandshakeV2Acceptance,
  createAgentHandshakeV2Acknowledgment,
  createAgentHandshakeV2Proposal,
  signAgentHandshakeV2Acceptance,
  signAgentHandshakeV2Proposal,
} from "../../src/agent-handshake/v2/protocol.mjs";
import {
  agentHandshakeV2DescriptorDigest,
  createAgentHandshakeV2DescriptorEnvelope,
} from "../../src/agent-handshake/v2/descriptor.mjs";
import {
  signAgentHandshakeV2Evidence,
} from "../../src/agent-handshake/v2/evidence.mjs";
import {
  createHostSessionKeyCertificate,
  hostSessionKeyCertificateDigest,
  rawEd25519PublicKey,
} from "../../src/agent-handshake/v2/host-key-certificate.mjs";
import { verifyAgentHandshakeV2Authorization } from "../../src/agent-handshake/v2/verdict.mjs";
import { buildAgentHandshakeV2Result } from "../../src/agent-handshake/v2/result.mjs";

export const SESSION_ID = "22222222-3333-4444-8555-666666666666";
export const REPOSITORY_SHA = "d".repeat(40);
export const SESSION_OPENED_AT_MS = "1786337000000";
export const SESSION_DEADLINE_MS = "1786337600000";
export const SESSION_OPENED_BLOCK = "6999";
export const NOW_MS = 1786337160000;
export const INITIATOR = privateKeyToAccount("0x" + "4".repeat(64));
export const RESPONDER = privateKeyToAccount("0x" + "5".repeat(64));
export const IDENTITY_POLICY = Object.freeze({
  erc8004: "required_fresh",
  chainId: "eip155:11155111",
  registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
});
export const TERMS = Object.freeze({
  reference: "NS-1847",
  statement: "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.",
  validForSeconds: "90",
  identityPolicy: IDENTITY_POLICY,
});

export function ed25519(keyId) {
  const seed = createHash("sha256").update(`clockchain-test:${keyId}`).digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      seed,
    ]),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey);
  return Object.freeze({
    keyId,
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
    publicKey: rawEd25519PublicKey(publicKey),
  });
}

function policy(role) {
  return Object.freeze({
    schema: "clockchain.agent-handshake-policy/v1",
    protocol: "clockchain.agent-handshake/v2",
    role,
    mcpOrigin: "https://mcp.clockchain.network",
    reference: TERMS.reference,
    statementDigest: agentHandshakeV2StatementDigest(TERMS),
    maxValidForSeconds: TERMS.validForSeconds,
    identityPolicy: IDENTITY_POLICY,
    externalBusinessActionsAllowed: false,
  });
}

function registration(account, agentId, block, fill) {
  return Object.freeze({
    sessionKeyAddress: account.address.toLowerCase(),
    policyDigest: localPolicyDigest(policy(agentId === "9452" ? "initiator" : "responder")),
    erc8004: Object.freeze({
      agentId,
      chainId: IDENTITY_POLICY.chainId,
      registryAddress: IDENTITY_POLICY.registryAddress,
      reference: IDENTITY_POLICY.chainId + ":" + IDENTITY_POLICY.registryAddress + ":" + agentId,
      registrationTx: "0x" + fill.repeat(64),
      registrationBlock: block,
    }),
  });
}

export async function buildV2Fixture() {
  const root = ed25519("root-2026-08");
  const host = ed25519("session-host");
  const hostSessionKeyCertificate = createHostSessionKeyCertificate({
    certificate: {
      schema: "clockchain.host-session-key/v1",
      rootKid: root.keyId,
      sessionId: SESSION_ID,
      repositorySha: REPOSITORY_SHA,
      sessionPublicKey: host.publicKey,
      validFromMs: SESSION_OPENED_AT_MS,
      validUntilMs: SESSION_DEADLINE_MS,
    },
    root: { keyId: root.keyId, privateKeyPem: root.privateKeyPem },
  });
  const policies = Object.freeze({ initiator: policy("initiator"), responder: policy("responder") });
  const parties = Object.freeze({
    initiator: registration(INITIATOR, "9452", "7000", "a"),
    responder: registration(RESPONDER, "9453", "7001", "b"),
  });
  const proposalEnvelope = await signAgentHandshakeV2Proposal({
    proposal: {
      schema: "clockchain.agent-handshake-proposal/v2",
      protocol: "clockchain.agent-handshake/v2",
      sessionId: SESSION_ID,
      repositorySha: REPOSITORY_SHA,
      reference: TERMS.reference,
      statementDigest: agentHandshakeV2StatementDigest(TERMS),
      identityPolicy: IDENTITY_POLICY,
      initiator: parties.initiator,
      responder: parties.responder,
      issuedAtMs: "1786337100000",
      expiresAtMs: "1786337190000",
      externalBusinessActionPerformed: false,
    },
    signMessage: (bytes) => INITIATOR.signMessage({ message: { raw: bytes } }),
  });
  const acceptanceEnvelope = await signAgentHandshakeV2Acceptance({
    acceptance: {
      schema: "clockchain.agent-handshake-acceptance/v2",
      protocol: "clockchain.agent-handshake/v2",
      sessionId: SESSION_ID,
      repositorySha: REPOSITORY_SHA,
      reference: TERMS.reference,
      statementDigest: agentHandshakeV2StatementDigest(TERMS),
      identityPolicy: IDENTITY_POLICY,
      initiator: parties.initiator,
      responder: parties.responder,
      proposalDigest: agentHandshakeV2ProposalDigest(proposalEnvelope),
      decision: "ACCEPTED",
      issuedAtMs: "1786337160000",
      expiresAtMs: "1786337190000",
      externalBusinessActionPerformed: false,
    },
    proposalEnvelope,
    signMessage: (bytes) => RESPONDER.signMessage({ message: { raw: bytes } }),
  });
  const descriptorEnvelope = createAgentHandshakeV2DescriptorEnvelope({
    agreementExpiresAtMs: "1786337190000",
    externalBusinessActionPerformed: false,
    hostSessionKeyCertificateDigest: hostSessionKeyCertificateDigest(hostSessionKeyCertificate),
    identityPolicy: IDENTITY_POLICY,
    initiator: parties.initiator,
    operatorPublicKey: host.publicKey,
    protocol: "clockchain.agent-handshake/v2",
    reference: TERMS.reference,
    repositorySha: REPOSITORY_SHA,
    responder: parties.responder,
    schema: "clockchain.agent-handshake-descriptor/v2",
    sessionId: SESSION_ID,
    sessionOpenedAtMs: SESSION_OPENED_AT_MS,
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
    statementDigest: agentHandshakeV2StatementDigest(TERMS),
  }, { keyId: host.keyId, privateKeyPem: host.privateKeyPem });
  const transitionBase = {
    expiresAtMs: "1786337190000",
    externalBusinessActionPerformed: false,
    initiator: parties.initiator,
    reference: TERMS.reference,
    responder: parties.responder,
    sessionDigest: agentHandshakeV2DescriptorDigest(descriptorEnvelope.descriptor),
    statementDigest: agentHandshakeV2StatementDigest(TERMS),
  };
  const proposed = createAgentHandshakeV2Proposal(transitionBase);
  const accepted = createAgentHandshakeV2Acceptance({
    ...transitionBase,
    predecessor: agentHandshakeV2TransitionDigest(proposed),
  }, proposed);
  const acknowledged = createAgentHandshakeV2Acknowledgment({
    ...transitionBase,
    predecessor: agentHandshakeV2TransitionDigest(accepted),
  }, accepted);
  const transitions = Object.freeze([proposed, accepted, acknowledged]);
  const receipts = Object.freeze(transitions.map((transition, index) => Object.freeze({
    blockHeight: String(7010 + index),
    blockTimeRaw: "2026-08-09T17:0" + index + ":00.000Z",
    digest: agentHandshakeV2TransitionDigest(transition),
    kind: ["proposal", "acceptance", "acknowledgment"][index],
    ledgerId: [
      "33333333-4444-4555-8666-777777777770",
      "33333333-4444-4555-8666-777777777771",
      "33333333-4444-4555-8666-777777777772",
    ][index],
  })));
  const evidence = {};
  for (const [role, account] of [["initiator", INITIATOR], ["responder", RESPONDER]]) {
    evidence[role] = await signAgentHandshakeV2Evidence({
      result: {
        externalBusinessActionPerformed: false,
        party: parties[role],
        policyDigest: parties[role].policyDigest,
        reference: TERMS.reference,
        repositorySha: REPOSITORY_SHA,
        role,
        schema: "clockchain.agent-handshake-party-result/v2",
        sessionDigest: transitionBase.sessionDigest,
        statementDigest: transitionBase.statementDigest,
        transitionDigests: transitions.map(agentHandshakeV2TransitionDigest),
      },
      signMessage: (bytes) => account.signMessage({ message: { raw: bytes } }),
    });
  }
  const verdict = await verifyAgentHandshakeV2Authorization({
    acceptanceEnvelope,
    descriptorEnvelope,
    evidence,
    expectedHostSessionKeyCertificateDigest: hostSessionKeyCertificateDigest(hostSessionKeyCertificate),
    expectedPublicKey: host.publicKey,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    expectedTerms: TERMS,
    nowMs: NOW_MS,
    proposalEnvelope,
    receipts,
    resolveRegistration: async (agentId) => ({
      owner: parties[agentId === "9452" ? "initiator" : "responder"].sessionKeyAddress,
      registrationBlock: parties[agentId === "9452" ? "initiator" : "responder"].erc8004.registrationBlock,
    }),
    transitions,
  });
  const resultEnvelope = buildAgentHandshakeV2Result({
    hostSessionKeyCertificate,
    issuedAtMs: "1786337180000",
    keyId: host.keyId,
    parties,
    privateKeyPem: host.privateKeyPem,
    sessionId: SESSION_ID,
    verdict,
  });
  return Object.freeze({
    acceptanceEnvelope,
    descriptorEnvelope,
    evidence: Object.freeze(evidence),
    host,
    hostSessionKeyCertificate,
    parties,
    policies,
    proposalEnvelope,
    receipts,
    resultEnvelope,
    root,
    transitions,
    verdict,
  });
}
