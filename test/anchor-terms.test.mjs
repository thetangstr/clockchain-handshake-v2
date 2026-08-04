// A receipt has to say what it was a receipt FOR.
//
// transitionToAnchor kept six fields and discarded transition.message, so the
// board could prove a receipt existed and say nothing about its contents — no
// amount, no expiry, no sequence, no session binding, no signer. Everything
// needed was already inside the bytes that were signed and anchored; it was
// simply being thrown away on the way to the display.
//
// These fields are display-only and carry no authority: the verifier re-derives
// its verdict from the evidence packages, never from a snapshot. What they must
// be is FAITHFUL — every value lifted verbatim from the signed message, nothing
// computed, nothing added.
import assert from "node:assert/strict";
import test from "node:test";

import {
  ANCHOR_KEYS,
  SIGNED_BY_KEYS,
  TERMS_KEYS,
  validateSnapshot,
} from "../src/monitor/snapshot.mjs";

const SESSION_DIGEST = "d".repeat(64);
const PREDECESSOR = "2731906";

function anchor(kind, blockHeight, overrides = {}) {
  return {
    blockHeight,
    blockTime: 1_700_000_000_000,
    explorerUrl: `https://relay.example/v1/blocks/${blockHeight}`,
    kind,
    ledgerId: `${kind[0].repeat(8)}-1111-4111-8111-111111111111`.replace(
      /^(.{8})/,
      (m) => m.toLowerCase().replace(/[^0-9a-f]/g, "a"),
    ),
    receipt: { anchoredHash: "a".repeat(64), digest: "a".repeat(64) },
    signedBy: { address: "0x" + "b".repeat(40), agentId: "9400" },
    terms: {
      currency: "USD",
      expirySeconds: "600",
      predecessor: kind === "proposal" ? null : PREDECESSOR,
      sequence: kind === "proposal" ? "1" : kind === "acceptance" ? "2" : "3",
      sessionDigest: SESSION_DIGEST,
      value: "100",
      ...overrides,
    },
  };
}

function snapshotWith(anchors) {
  return {
    anchors,
    currentStage: "ACKNOWLEDGED",
    funding: null,
    heartbeat: { payee: null, payer: null, verifier: null },
    identities: null,
    paymentMoved: false,
    reasonCode: null,
    schema: "clockchain.handshake-snapshot/v1",
    sessionId: "00000000-0000-4000-8000-000000000000",
    stageHistory: [{ atMs: 1, status: "ACKNOWLEDGED" }],
    subjectRun: "stakeholder",
    updatedAtMs: 2,
    verdict: null,
  };
}

test("the anchor shape carries the signed terms and the signer", () => {
  assert.ok(ANCHOR_KEYS.includes("terms"), "an anchor must carry what was agreed");
  assert.ok(ANCHOR_KEYS.includes("signedBy"), "an anchor must carry who agreed it");
  // Scope, cap and expiry all live in these fields; if one is dropped the
  // receipt stops being self-describing.
  for (const field of ["currency", "value", "expirySeconds", "sequence", "sessionDigest", "predecessor"]) {
    assert.ok(TERMS_KEYS.includes(field), `terms must carry ${field}`);
  }
  assert.deepEqual([...SIGNED_BY_KEYS].sort(), ["address", "agentId"]);
});

test("a fully populated set of three receipts validates", () => {
  const snapshot = snapshotWith({
    acceptance: anchor("acceptance", "200"),
    acknowledgment: anchor("acknowledgment", "300"),
    proposal: anchor("proposal", "100"),
  });
  assert.equal(validateSnapshot(snapshot), true);
});

test("terms are optional, because a run stopped before anchoring has none", () => {
  const bare = anchor("proposal", "100");
  bare.terms = null;
  bare.signedBy = null;
  assert.equal(
    validateSnapshot(snapshotWith({ acceptance: null, acknowledgment: null, proposal: bare })),
    true,
  );
});

test("a malformed amount, expiry, or signer is refused rather than displayed", () => {
  const cases = [
    ["value", "one hundred"],
    ["expirySeconds", "ten minutes"],
    ["sequence", "first"],
    ["currency", ""],
  ];
  for (const [field, bad] of cases) {
    const broken = anchor("proposal", "100", { [field]: bad });
    assert.throws(
      () => validateSnapshot(snapshotWith({ acceptance: null, acknowledgment: null, proposal: broken })),
      /Handshake snapshot is invalid/,
      `terms.${field} = ${JSON.stringify(bad)} must be refused`,
    );
  }

  const badSigner = anchor("proposal", "100");
  badSigner.signedBy = { address: "0xNOTLOWERCASE", agentId: "9400" };
  assert.throws(
    () => validateSnapshot(snapshotWith({ acceptance: null, acknowledgment: null, proposal: badSigner })),
    /Handshake snapshot is invalid/,
    "a signer address that is not a lowercase 0x address must be refused",
  );
});

test("the first receipt has no predecessor and the later ones must", () => {
  // This is what makes the ordering a property of the chain rather than of our
  // own logs, so it is worth asserting the shape can express it.
  const proposal = anchor("proposal", "100");
  assert.equal(proposal.terms.predecessor, null);
  for (const kind of ["acceptance", "acknowledgment"]) {
    assert.equal(anchor(kind, "200").terms.predecessor, PREDECESSOR);
  }
});

test("an object predecessor is refused, not stringified into the display", () => {
  // The bug this pins reached a live board. The predecessor on the wire is a
  // triple -- {anchoredHash, blockHeight, kind, ledgerId} -- and the operator
  // ran String() over it, so the receipt read "Follows [object Object]". Every
  // test passed, because the fixtures carried a hash string: they encoded the
  // same wrong assumption the code did. A real run caught it in one look.
  const broken = anchor("acceptance", "200");
  broken.terms.predecessor = {
    anchoredHash: "4f112eef",
    blockHeight: "2731906",
    kind: "proposal",
    ledgerId: "0db480de-744d-4c3a-bbd7-1f6b7627414f",
  };
  assert.throws(
    () => validateSnapshot(snapshotWith({ acceptance: broken, acknowledgment: null, proposal: null })),
    /Handshake snapshot is invalid/,
    "a triple must be refused rather than rendered as [object Object]",
  );

  const stringified = anchor("acceptance", "200");
  stringified.terms.predecessor = "[object Object]";
  assert.throws(
    () => validateSnapshot(snapshotWith({ acceptance: stringified, acknowledgment: null, proposal: null })),
    /Handshake snapshot is invalid/,
    "the stringified form must be refused too — that is what actually shipped",
  );
});
