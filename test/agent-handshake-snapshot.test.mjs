import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_HANDSHAKE_SNAPSHOT_SCHEMA,
  AgentHandshakeSnapshotError,
  buildAgentHandshakeSnapshot,
  validateAgentHandshakeSnapshot,
} from "../src/monitor/agent-snapshot.mjs";

const IDENTITY = Object.freeze({
  address: "0x00112233445566778899aabbccddeeff00112233",
  agentId: "9452",
  chainId: "11155111",
  reference: "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:9452",
  registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
});

function snapshot(overrides = {}) {
  return buildAgentHandshakeSnapshot({
    anchors: { acceptance: null, acknowledgment: null, proposal: null },
    currentStage: "IDENTITIES_REGISTERED",
    funding: { atMs: 1786337100000, funded: true },
    heartbeat: {
      checker: null,
      initiator: { lastSeenMs: 1786337100000 },
      responder: { lastSeenMs: 1786337100001 },
    },
    identities: {
      initiator: IDENTITY,
      responder: {
        ...IDENTITY,
        address: "0xffeeddccbbaa99887766554433221100ffeeddcc",
        agentId: "9453",
        reference: "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:9453",
      },
    },
    reasonCode: null,
    reference: "NS-1847",
    sessionId: "22222222-3333-4444-8555-666666666666",
    stageHistory: [
      { atMs: 1786337000000, status: "SESSION_STARTED" },
      { atMs: 1786337100000, status: "IDENTITIES_REGISTERED" },
    ],
    statement: "Northstar Logistics and Harbor Supply confirm that these two registered agents are authorized to communicate about shipment reference NS-1847 for the next 45 minutes.",
    subjectRun: "stakeholder",
    updatedAtMs: 1786337100001,
    verdict: null,
    ...overrides,
  });
}

test("generic snapshot carries two full identities without payment fields", () => {
  const value = snapshot();
  assert.equal(value.schema, AGENT_HANDSHAKE_SNAPSHOT_SCHEMA);
  assert.equal(validateAgentHandshakeSnapshot(value), true);
  assert.deepEqual(Object.keys(value.identities.initiator), [
    "address",
    "agentId",
    "chainId",
    "reference",
    "registryAddress",
  ]);
  const text = JSON.stringify(value).toLowerCase();
  for (const word of ["amount", "currency", "invoice", "payer", "payee", "payment", "requestor"]) {
    assert.equal(text.includes(word), false, word);
  }
});

test("generic anchors expose exact statement and predecessor facts", () => {
  const anchor = (kind, sequence, predecessor, height) => ({
    blockHeight: String(height),
    blockTime: 1786337200000 + height,
    explorerUrl: `https://example.test/${height}`,
    kind,
    ledgerId: `33333333-4444-4555-8666-77777777777${sequence}`,
    receipt: { ok: true },
    actor: kind === "acceptance"
      ? "responder"
      : kind === "proposal" ? "initiator" : "clockchain",
    terms: {
      expiresAtMs: "1786339800000",
      predecessor,
      reference: "NS-1847",
      sequence: String(sequence),
      sessionDigest: "a".repeat(64),
      statementDigest: "b".repeat(64),
    },
  });
  const value = snapshot({
    anchors: {
      acceptance: anchor("acceptance", 2, "c".repeat(64), 7001),
      acknowledgment: anchor("acknowledgment", 3, "d".repeat(64), 7002),
      proposal: anchor("proposal", 1, null, 7000),
    },
    currentStage: "CERTIFIED",
    stageHistory: [
      { atMs: 1786337000000, status: "SESSION_STARTED" },
      { atMs: 1786337200000, status: "CERTIFIED" },
    ],
    updatedAtMs: 1786337200000,
    verdict: {
      externalActionPerformed: false,
      outcome: "VERIFIED",
      reference: "NS-1847",
      sessionDigest: "a".repeat(64),
      statementDigest: "b".repeat(64),
    },
  });
  assert.equal(validateAgentHandshakeSnapshot(value), true);
  assert.equal(value.anchors.acknowledgment.terms.predecessor, "d".repeat(64));
});

test("snapshot rejects extra keys, mismatched identities, and fabricated verdicts", () => {
  const fabricated = structuredClone(snapshot());
  fabricated.verdict = {
    externalActionPerformed: false,
    outcome: "VERIFIED",
    reference: "NS-1847",
    sessionDigest: "a".repeat(64),
    statementDigest: "b".repeat(64),
  };
  const duplicateIdentity = structuredClone(snapshot());
  duplicateIdentity.identities.responder = duplicateIdentity.identities.initiator;
  const cases = [
    { ...snapshot(), amount: "0" },
    duplicateIdentity,
    fabricated,
  ];
  for (const value of cases) {
    assert.throws(
      () => validateAgentHandshakeSnapshot(value),
      (error) => error instanceof AgentHandshakeSnapshotError,
    );
  }
});
