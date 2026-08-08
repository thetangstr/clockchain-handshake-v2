import assert from "node:assert/strict";
import { test } from "node:test";

import { canonicalBytes } from "../src/core/canonical.mjs";
import { transitionToAnchor, anchorToWireReport } from "../src/monitor/anchor.mjs";
import {
  assertHandshakeRepositoryKey,
  issuedAtMsFromLedgerTimestamp,
  selectRequestorRoster,
} from "../src/roles/payer.mjs";

function transition(kind, blockHeight) {
  return {
    blockTimeMs: 1_700_000_000_000,
    blockTimeRaw: "1700000000000",
    digest: `${kind[0]}`.repeat(64),
    message: {
      amount: { currency: "USD", value: "100" },
      expirySeconds: "600",
      payee: { address: "0x" + "a".repeat(40), agentId: "11" },
      payer: { address: "0x" + "b".repeat(40), agentId: "22" },
      predecessor: kind === "proposal" ? null : { blockHeight: "100" },
      sequence: kind === "proposal" ? "1" : kind === "acceptance" ? "2" : "3",
      sessionDigest: "c".repeat(64),
    },
    onChain: {
      anchoredHash: `${kind.at(-1)}`.repeat(64),
      blockHeight: String(blockHeight),
      ledgerId: `${kind}-ledger`,
    },
  };
}

function hasNumber(value) {
  if (typeof value === "number") return true;
  if (Array.isArray(value)) return value.some(hasNumber);
  if (value && typeof value === "object") return Object.values(value).some(hasNumber);
  return false;
}

test("payer parses Clockchain ledger timestamps as UTC DD-MM-YYYY milliseconds", () => {
  assert.equal(
    issuedAtMsFromLedgerTimestamp({ madMarzulloTime: "24-06-2026_22:49:40:092" }),
    Date.UTC(2026, 5, 24, 22, 49, 40, 92),
  );
});

test("payer rejects discovery repository key substitution before running its role", () => {
  assert.throws(
    () => assertHandshakeRepositoryKey({
      discovery: { operatorPublicKey: "expected-public-key" },
      handshake: { body: { repositoryPublicKey: "substituted-public-key" } },
    }),
    /signed terms name a different session host key/u,
  );
});

test("payer roster keeps the first requestor identity and ignores party_ready for another address", () => {
  const address = `0x${"1".repeat(40)}`;
  const selected = selectRequestorRoster([
    { kind: "identity_ready", role: "requestor", senderKey: "requestor-key", body: { address } },
    { kind: "party_ready", role: "requestor", senderKey: "requestor-key", body: { address: `0x${"2".repeat(40)}`, agentId: "wrong" } },
    { kind: "party_ready", role: "requestor", senderKey: "requestor-key", body: { address: address.toUpperCase(), agentId: "42" } },
  ]);

  assert.equal(selected.ready, true);
  assert.equal(selected.identityReady.body.address, address);
  assert.equal(selected.partyReady.body.agentId, "42");
});

test("payer roster ignores same-address party_ready from a different sender key", () => {
  const address = `0x${"3".repeat(40)}`;
  const selected = selectRequestorRoster([
    { kind: "identity_ready", role: "requestor", senderKey: "requestor-key", body: { address } },
    { kind: "party_ready", role: "requestor", senderKey: "other-key", body: { address, agentId: "wrong" } },
    { kind: "party_ready", role: "requestor", senderKey: "requestor-key", body: { address, agentId: "99" } },
  ]);

  assert.equal(selected.ready, true);
  assert.equal(selected.partyReady.body.agentId, "99");
});

test("payer anchor report converts board anchors into canonical-safe wire anchors", () => {
  const boardAnchors = {
    acceptance: transitionToAnchor("acceptance", transition("acceptance", 3083435), { relayUrl: "http://relay.test" }),
    acknowledgment: transitionToAnchor("acknowledgment", transition("acknowledgment", 3083437), { relayUrl: "http://relay.test" }),
    proposal: transitionToAnchor("proposal", transition("proposal", 3083414), { relayUrl: "http://relay.test" }),
  };

  assert.throws(
    () => canonicalBytes({ anchors: boardAnchors, paymentMoved: false }),
    (error) => error?.code === "CANONICAL_NUMBER",
  );

  const wireBody = {
    anchors: {
      acceptance: anchorToWireReport(boardAnchors.acceptance),
      acknowledgment: anchorToWireReport(boardAnchors.acknowledgment),
      proposal: anchorToWireReport(boardAnchors.proposal),
    },
    paymentMoved: false,
  };

  assert.equal(hasNumber(wireBody), false);
  assert.equal(wireBody.anchors.proposal.blockTime, "1700000000000");
  assert.doesNotThrow(() => canonicalBytes(wireBody));
});
