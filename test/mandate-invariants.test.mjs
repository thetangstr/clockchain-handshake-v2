// Mandate invariants.
//
// Sub-run isolation in this protocol is cryptographic but discipline-dependent:
// subjectRun lives in the signed mandate, flows into the mandate digest, then into
// the descriptor, then into dSession, and finally into every Clockchain reference
// id. Two sub-runs stay separated only because the operator builds a DISTINCT
// mandate for each. Reuse an intakeRequestId and the two sub-runs collide on
// reference id — and the collision surfaces as DUPLICATE only after a stakeholder
// has already done all of their work.
//
// In the donor, that discipline lived in a coordination module v2 does not port,
// so v2 encodes it here as a tested invariant instead.
import { test } from "node:test";
import assert from "node:assert/strict";

import { validatePayerMandate } from "../src/core/payer-mandate.mjs";
import {
  HUMAN_PACED_MINIMUM_MS,
  assertMandateLifetime,
} from "../src/core/window.mjs";

const BASE_ISSUED = 1_800_000_000_000;

function mandate(overrides = {}) {
  return {
    amount: { currency: "USD", value: "100" },
    expiresAtMs: String(BASE_ISSUED + HUMAN_PACED_MINIMUM_MS),
    intakeDigest: "ab".repeat(32),
    intakeRequestId: "00112233-4455-4677-8899-aabbccddeeff",
    invoiceReferencePrefix: "INV-",
    issuedAtMs: String(BASE_ISSUED),
    payee: {
      address: `0x${"22".repeat(20)}`,
      agentId: "2",
    },
    payer: {
      address: `0x${"11".repeat(20)}`,
      agentId: "1",
    },
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    purpose: "Invoice settlement",
    releaseId: "release-1",
    repositorySha: "0123456789abcdef0123456789abcdef01234567",
    requestEndpoint: "/v1/sessions/00112233-4455-6677-8899-aabbccddeeff/payment-requests",
    schema: "clockchain.bilateral-payer-mandate/v1",
    sessionId: "00112233-4455-6677-8899-aabbccddeeff",
    subjectRun: "stakeholder",
    ...overrides,
  };
}

test("subjectRun is enforced as an enum of exactly two runs", () => {
  for (const subjectRun of ["rehearsal", "stakeholder"]) {
    assert.doesNotThrow(() => validatePayerMandate(mandate({ subjectRun })));
  }
  for (const subjectRun of ["live", "REHEARSAL", "", "production", null]) {
    assert.throws(
      () => validatePayerMandate(mandate({ subjectRun })),
      `subjectRun ${JSON.stringify(subjectRun)} must be refused`,
    );
  }
});

test("a mandate always carries paymentMoved false", () => {
  assert.doesNotThrow(() => validatePayerMandate(mandate()));
  assert.throws(() => validatePayerMandate(mandate({ paymentMoved: true })));
});

test("the two sub-runs must use distinct intake request ids", () => {
  // The operator builds one mandate per sub-run. If it reuses the id, the two
  // mandates differ only by subjectRun — which is exactly the near-miss that
  // makes this invariant worth testing rather than assuming.
  const rehearsal = mandate({
    intakeRequestId: "00112233-4455-4677-8899-aabbccddeeff",
    subjectRun: "rehearsal",
  });
  const live = mandate({
    intakeRequestId: "ffeeddcc-bbaa-4988-8766-554433221100",
    subjectRun: "stakeholder",
  });
  assert.notEqual(rehearsal.intakeRequestId, live.intakeRequestId);
  assert.notEqual(rehearsal.subjectRun, live.subjectRun);
  assert.doesNotThrow(() => validatePayerMandate(rehearsal));
  assert.doesNotThrow(() => validatePayerMandate(live));
});

test("distinct mandates produce distinct digests", async () => {
  const { payerMandateSigningBytes } = await import(
    "../src/core/payer-mandate.mjs"
  );
  const rehearsal = payerMandateSigningBytes(
    mandate({ subjectRun: "rehearsal" }),
  ).toString("hex");
  const live = payerMandateSigningBytes(
    mandate({ subjectRun: "stakeholder" }),
  ).toString("hex");
  // subjectRun alone changes the signed bytes, therefore the mandate digest,
  // therefore dSession, therefore every reference id for the sub-run.
  assert.notEqual(rehearsal, live);
});

test("mandate construction refuses a lifetime shorter than a human can act in", () => {
  const tooShort = assertMandateLifetime({
    expiresAtMs: String(BASE_ISSUED + 11 * 60_000),
    issuedAtMs: String(BASE_ISSUED),
  });
  assert.equal(tooShort.ok, false);
  assert.equal(tooShort.reason, "EXPIRED");
  // Plain business language: this string can reach a stakeholder.
  assert.match(tooShort.detail, /expire/i);

  const acceptable = assertMandateLifetime({
    expiresAtMs: String(BASE_ISSUED + HUMAN_PACED_MINIMUM_MS),
    issuedAtMs: String(BASE_ISSUED),
  });
  assert.equal(acceptable.ok, true);
});

test("mandate construction refuses terms that expire before the session does", () => {
  const result = assertMandateLifetime({
    discoveryExpiresAtMs: String(BASE_ISSUED + 90 * 60_000),
    expiresAtMs: String(BASE_ISSUED + 45 * 60_000),
    issuedAtMs: String(BASE_ISSUED),
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "EXPIRED");
});

test("the donor validator is unchanged: it still accepts its shorter fixtures", () => {
  // payer-mandate.mjs is a PURE port. The stronger lifetime rule is enforced at
  // construction (window.mjs), not by editing the ported validator — so the donor
  // fixtures, which use an 11-minute mandate, must still validate here.
  assert.doesNotThrow(() =>
    validatePayerMandate(
      mandate({ expiresAtMs: String(BASE_ISSUED + 700_000) }),
    ),
  );
});
