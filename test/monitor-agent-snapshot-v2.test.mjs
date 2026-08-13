import assert from "node:assert/strict";
import test from "node:test";

import {
  buildAgentHandshakeV2Snapshot,
  validateAgentHandshakeV2Snapshot,
} from "../src/monitor/agent-snapshot-v2.mjs";

const registry = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
const identityPolicy = {
  erc8004: "required_fresh",
  chainId: "eip155:11155111",
  registryAddress: registry,
};
const registration = (agentId, address, fill, block) => ({
  agentId,
  chainId: "eip155:11155111",
  registryAddress: registry,
  reference: "eip155:11155111:" + registry + ":" + agentId,
  registrationTx: "0x" + fill.repeat(64),
  registrationBlock: block,
});
const receipt = (kind, index) => ({
  blockHeight: String(7010 + index),
  blockTimeRaw: "2026-08-09T17:0" + index + ":00.000Z",
  digest: String(index + 1).repeat(64),
  explorerUrl: "https://clockchain.network/ledger/33333333-4444-4555-8666-77777777777" + index,
  kind,
  ledgerId: "33333333-4444-4555-8666-77777777777" + index,
});

export function completeV2Snapshot() {
  return {
    schema: "clockchain.agent-handshake-snapshot/v2",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: "22222222-3333-4444-8555-666666666666",
    repositorySha: "d".repeat(40),
    hostTrust: {
      rootKid: "root-2026-08",
      rootFingerprint: "a".repeat(64),
      sessionPublicKey: "A".repeat(43) + "=",
      sessionKeyCertificateDigest: "b".repeat(64),
    },
    timing: {
      createdAtMs: 1786337000000,
      invitationExpiresAtMs: 1786337300000,
      sessionDeadlineMs: 1786337600000,
      agreementValidForSeconds: "90",
    },
    invitation: {
      createdAtMs: 1786337001000,
      responderClaimedAtMs: 1786337002000,
    },
    terms: {
      reference: "NS-1847",
      statement: "Northstar and Harbor authorize these agents to communicate.",
      identityPolicy,
    },
    policies: {
      initiator: { digest: "c".repeat(64), committedAtMs: 1786337003000 },
      responder: { digest: "d".repeat(64), committedAtMs: 1786337004000 },
    },
    parties: {
      initiator: {
        sessionKeyAddress: "0x" + "1".repeat(40),
        erc8004: registration("9452", "0x" + "1".repeat(40), "e", "7000"),
      },
      responder: {
        sessionKeyAddress: "0x" + "2".repeat(40),
        erc8004: registration("9453", "0x" + "2".repeat(40), "f", "7001"),
      },
    },
    statements: {
      proposalDigest: "1".repeat(64),
      acceptanceDigest: "2".repeat(64),
    },
    receipts: {
      proposal: receipt("proposal", 0),
      acceptance: receipt("acceptance", 1),
      acknowledgment: receipt("acknowledgment", 2),
    },
    evidence: {
      initiator: { digest: "3".repeat(64), receivedAtMs: 1786337180000 },
      responder: { digest: "4".repeat(64), receivedAtMs: 1786337180001 },
    },
    checker: { stage: "VERIFIED", lastSeenMs: 1786337181000 },
    certificate: {
      digest: "5".repeat(64),
      issuedAtMs: 1786337182000,
      outcome: "VERIFIED",
    },
    freshness: {
      initiator: { lastSeenMs: 1786337180000 },
      responder: { lastSeenMs: 1786337180001 },
      host: { lastSeenMs: 1786337181000 },
      checker: { lastSeenMs: 1786337181000 },
    },
    failure: null,
    externalBusinessActionPerformed: false,
  };
}

test("v2 snapshot exposes every public proof fact without capabilities or secrets", () => {
  const value = completeV2Snapshot();
  assert.deepEqual(buildAgentHandshakeV2Snapshot(value), value);
  assert.equal(validateAgentHandshakeV2Snapshot(value), true);
  const publicText = JSON.stringify(value).toLowerCase();
  for (const forbidden of [
    "roleaccess", "invitationtoken", "privatekey", "signaturehex", "providercredential",
    "fundingcredential", "privatepath",
  ]) assert.equal(publicText.includes(forbidden), false, forbidden);
});

test("each artifact may be absent independently without being fabricated by a later field", () => {
  const value = completeV2Snapshot();
  value.statements.proposalDigest = null;
  value.receipts.acceptance = null;
  value.parties.responder = null;
  value.certificate = null;
  value.checker = { stage: "VERIFYING", lastSeenMs: 1786337181000 };
  assert.equal(validateAgentHandshakeV2Snapshot(value), true);
  assert.equal(buildAgentHandshakeV2Snapshot(value).receipts.acceptance, null);
});

test("an invitation may be ready but not created, and cannot be claimed before creation", () => {
  const ready = completeV2Snapshot();
  ready.invitation = { createdAtMs: null, responderClaimedAtMs: null };
  ready.policies = { initiator: null, responder: null };
  ready.parties = { initiator: null, responder: null };
  ready.statements = { proposalDigest: null, acceptanceDigest: null };
  ready.receipts = { proposal: null, acceptance: null, acknowledgment: null };
  ready.evidence = { initiator: null, responder: null };
  ready.checker = { stage: "WAITING", lastSeenMs: ready.timing.createdAtMs };
  ready.certificate = null;
  ready.freshness = {
    initiator: null,
    responder: null,
    host: { lastSeenMs: ready.timing.createdAtMs },
    checker: { lastSeenMs: ready.timing.createdAtMs },
  };
  assert.equal(validateAgentHandshakeV2Snapshot(ready), true);
  ready.invitation.responderClaimedAtMs = ready.timing.createdAtMs + 2;
  assert.throws(() => validateAgentHandshakeV2Snapshot(ready));
  ready.invitation = {
    createdAtMs: ready.timing.invitationExpiresAtMs,
    responderClaimedAtMs: null,
  };
  assert.throws(() => validateAgentHandshakeV2Snapshot(ready));
});

test("unknown keys, partial nested facts, duplicate parties, secret-shaped fields, and false invariants reject", () => {
  const base = completeV2Snapshot();
  for (const value of [
    { ...base, extra: true },
    { ...base, roleAccess: "secret" },
    { ...base, externalBusinessActionPerformed: true },
    { ...base, hostTrust: { ...base.hostTrust, extra: true } },
    { ...base, policies: { ...base.policies, initiator: { digest: "c".repeat(64) } } },
    { ...base, parties: { ...base.parties, responder: base.parties.initiator } },
    { ...base, receipts: { ...base.receipts, proposal: { ...base.receipts.proposal, kind: "acceptance" } } },
    { ...base, certificate: { ...base.certificate, outcome: "FAILED" } },
  ]) assert.throws(() => validateAgentHandshakeV2Snapshot(value));
});

test("not-required identity has null registration and required modes require complete registration", () => {
  const value = completeV2Snapshot();
  value.terms.identityPolicy = { erc8004: "not_required", chainId: null, registryAddress: null };
  value.parties.initiator.erc8004 = null;
  value.parties.responder.erc8004 = null;
  assert.equal(validateAgentHandshakeV2Snapshot(value), true);
  value.parties.initiator.erc8004 = registration("9452", value.parties.initiator.sessionKeyAddress, "e", "7000");
  assert.throws(() => validateAgentHandshakeV2Snapshot(value));
});
