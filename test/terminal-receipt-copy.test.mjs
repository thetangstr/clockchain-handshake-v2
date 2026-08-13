import assert from "node:assert/strict";
import test from "node:test";

import {
  TerminalReceiptCopyError,
  formatTerminalReceiptCopy,
} from "../src/testing/terminal-receipt-copy.mjs";

const CERTIFICATE_DIGEST = "d".repeat(64);

function evidenceFixture() {
  return {
    schema: "clockchain.fresh-agent-canary-evidence/v1",
    monitor: {
      certificate: {
        digest: CERTIFICATE_DIGEST,
        issuedAtMs: Date.UTC(2026, 7, 13, 20, 52, 36),
        outcome: "VERIFIED",
      },
      receipts: {
        proposal: {
          blockHeight: "3560023",
          digest: "a".repeat(64),
          kind: "proposal",
          ledgerId: "1cd46000-2a55-4d25-bf14-7e2e2109aca0",
        },
        acceptance: {
          blockHeight: "3560033",
          digest: "b".repeat(64),
          kind: "acceptance",
          ledgerId: "62beab92-703c-4eed-87f2-6b8bba29aa46",
        },
        acknowledgment: {
          blockHeight: "3560037",
          digest: "c".repeat(64),
          kind: "acknowledgment",
          ledgerId: "b3c16c4d-f5fd-4f27-8861-556b7ff69b17",
        },
      },
      sessionId: "c3681923-e837-4774-9ea4-38a6d9736532",
    },
    roles: {
      initiator: {
        address: "0x1111111111111111111111111111111111111111",
        certificateDigest: CERTIFICATE_DIGEST,
        certificateVerified: true,
        erc8004: {
          agentId: "9621",
          registrationBlock: "11482629",
          registrationTx: `0x${"1".repeat(64)}`,
        },
        externalBusinessActionPerformed: false,
      },
      responder: {
        address: "0x2222222222222222222222222222222222222222",
        certificateDigest: CERTIFICATE_DIGEST,
        certificateVerified: true,
        erc8004: {
          agentId: "9622",
          registrationBlock: "11482630",
          registrationTx: `0x${"2".repeat(64)}`,
        },
        externalBusinessActionPerformed: false,
      },
    },
  };
}

test("formats separate party identities with one shared certificate and receipt chain", () => {
  const evidence = evidenceFixture();
  evidence.roles.initiator.privateKey = "PRIVATE_KEY_CANARY";
  evidence.roles.initiator.roleAccess = "ROLE_ACCESS_CANARY";
  evidence.roles.initiator.statePath = "/private/tmp/party-state";
  const payer = formatTerminalReceiptCopy(evidence, "initiator");
  const requestor = formatTerminalReceiptCopy(evidence, "responder");

  assert.match(payer, /HANDSHAKE COMPLETE — PAYER COPY/);
  assert.match(requestor, /HANDSHAKE COMPLETE — REQUESTOR COPY/);
  assert.match(payer, /ERC-8004 agent: #9621/);
  assert.doesNotMatch(payer, /#9622/);
  assert.match(requestor, /ERC-8004 agent: #9622/);
  assert.doesNotMatch(requestor, /#9621/);
  assert.match(payer, new RegExp(`Certificate digest: ${CERTIFICATE_DIGEST}`));
  assert.match(requestor, new RegExp(`Certificate digest: ${CERTIFICATE_DIGEST}`));
  assert.match(payer, /Issued: 2026-08-13 20:52:36 UTC/);
  assert.match(payer, /Session: c3681923-e837-4774-9ea4-38a6d9736532/);
  assert.ok(payer.indexOf("Receipt 1 — Proposal") < payer.indexOf("Receipt 2 — Acceptance"));
  assert.ok(payer.indexOf("Receipt 2 — Acceptance") < payer.indexOf("Receipt 3 — Acknowledgment"));
  for (const value of [
    "1cd46000-2a55-4d25-bf14-7e2e2109aca0",
    "62beab92-703c-4eed-87f2-6b8bba29aa46",
    "b3c16c4d-f5fd-4f27-8861-556b7ff69b17",
    "3560023",
    "3560033",
    "3560037",
    "a".repeat(64),
    "b".repeat(64),
    "c".repeat(64),
  ]) {
    assert.ok(payer.includes(value));
    assert.ok(requestor.includes(value));
  }
  assert.match(payer, /No external business action occurred\./);
  assert.match(requestor, /No external business action occurred\./);
  for (const forbidden of [
    "PRIVATE_KEY_CANARY",
    "ROLE_ACCESS_CANARY",
    "/private/tmp/party-state",
  ]) {
    assert.doesNotMatch(payer, new RegExp(forbidden.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));
  }
  assert.ok(payer.endsWith("\n"));
  assert.ok(requestor.endsWith("\n"));
});

test("fails closed before returning partial receipt text", () => {
  const cases = [
    ["unknown role", (value) => value, "payer"],
    ["missing party", (value) => { delete value.roles.initiator; }, "initiator"],
    ["malformed certificate digest", (value) => { value.monitor.certificate.digest = "short"; }, "initiator"],
    ["party certificate mismatch", (value) => { value.roles.initiator.certificateDigest = "e".repeat(64); }, "initiator"],
    ["malformed issue time", (value) => { value.monitor.certificate.issuedAtMs = Number.NaN; }, "initiator"],
    ["missing receipt", (value) => { delete value.monitor.receipts.acceptance; }, "initiator"],
    ["wrong receipt kind", (value) => { value.monitor.receipts.acceptance.kind = "proposal"; }, "initiator"],
    ["missing ledger id", (value) => { value.monitor.receipts.proposal.ledgerId = ""; }, "initiator"],
    ["malformed receipt digest", (value) => { value.monitor.receipts.proposal.digest = "0x1"; }, "initiator"],
    ["malformed block height", (value) => { value.monitor.receipts.proposal.blockHeight = "03560023"; }, "initiator"],
    ["certificate not verified", (value) => { value.roles.initiator.certificateVerified = false; }, "initiator"],
    ["external action occurred", (value) => { value.roles.initiator.externalBusinessActionPerformed = true; }, "initiator"],
  ];

  for (const [name, mutate, role] of cases) {
    const value = evidenceFixture();
    mutate(value);
    assert.throws(
      () => formatTerminalReceiptCopy(value, role),
      TerminalReceiptCopyError,
      name,
    );
  }
});
