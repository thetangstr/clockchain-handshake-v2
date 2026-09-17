import assert from "node:assert/strict";
import test from "node:test";

import {
  NEGATIVE_CASES,
  OBSERVED_ONLY_CASES,
  runNegativeChecks,
} from "../scripts/negative-checks.mjs";

// The four cases are expensive (three ed25519 keypairs, six anchors, two
// full verifier passes) so the suite runs them once and asserts against the
// single report rather than re-running per assertion.
const report = await runNegativeChecks();
const gating = report.results.filter((result) => result.gating);

test("the control run is accepted, so a green table is not a broken fixture", () => {
  assert.equal(report.control.pass, true, report.control.detail);
});

test("all four negative cases are exercised", () => {
  assert.equal(NEGATIVE_CASES.length, 4);
  assert.deepEqual(
    gating.map((result) => result.id),
    ["REPLAY", "REORDER", "TAMPER", "DUPLICATE_FUNDING"],
  );
});

test("every negative case fails closed with the reason code the script records", () => {
  for (const result of gating) {
    assert.equal(
      result.code,
      result.expected,
      `${result.id} produced ${result.code ?? "no code"} (${result.detail ?? "no detail"})`,
    );
  }
});

test("the four cases produce four DISTINCT reason codes", () => {
  const codes = gating.map((result) => result.code);
  assert.equal(
    new Set(codes).size,
    4,
    `expected four distinct codes, got ${codes.join(", ")}`,
  );
  assert.equal(report.distinct, true);
});

test("no negative case closes without a named code", () => {
  for (const result of gating) {
    assert.equal(typeof result.code, "string", result.id);
    assert.match(result.code, /^[A-Z][A-Z_]+$/, result.id);
  }
});

// The public-vocabulary facts the script surfaces. They are asserted here so
// that a later change which gives duplicate funding a public code breaks this
// test and forces the script's recorded expectations to be updated with it.
test("the reason codes the four cases actually reach are recorded, not assumed", () => {
  const byId = new Map(gating.map((result) => [result.id, result]));
  assert.equal(byId.get("REORDER").code, "REORDERED");
  // (d) reports the pure journal's own internal namespace. That journal is a
  // pure port and duplicate-funding replay is not a legacy public reason.
  assert.equal(
    byId.get("DUPLICATE_FUNDING").code,
    "BILATERAL_FUNDING_REPLACED_TRANSFER",
  );
});

test("replay into a session that anchored its own run lands on the catch-all", () => {
  assert.equal(OBSERVED_ONLY_CASES.length, 1);
  const anchored = report.results.find(
    (result) => result.id === "REPLAY_ANCHORED",
  );
  assert.equal(anchored.gating, false);
  // Recorded as a finding about the vocabulary, not hidden: the frozen set has
  // no code meaning "this evidence belongs to a different run", so this variant
  // shares the generic FAILED with the tampered-signature case.
  assert.equal(anchored.code, "FAILED");
  const tamper = report.results.find((result) => result.id === "TAMPER");
  assert.equal(tamper.code, "FAILED");
});
