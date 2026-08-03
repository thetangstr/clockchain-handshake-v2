import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

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

// The three public-vocabulary facts the script surfaces. They are asserted here
// so that a later change which makes REORDERED or FUNDING_REPLAYED reachable, or
// which gives replay-into-a-live-session its own code, breaks this test and
// forces the script's recorded expectations to be updated with it.
test("the reason codes the four cases actually reach are recorded, not assumed", () => {
  const byId = new Map(gating.map((result) => [result.id, result]));
  // (b) does NOT reach REORDERED: that code has no emission site in src/.
  assert.equal(byId.get("REORDER").code, "MALFORMED");
  assert.notEqual(byId.get("REORDER").code, "REORDERED");
  // (d) does NOT reach FUNDING_REPLAYED: the ported journal refuses in its own
  // internal namespace, and the journal is a pure port that must not be edited.
  assert.equal(
    byId.get("DUPLICATE_FUNDING").code,
    "BILATERAL_FUNDING_REPLACED_TRANSFER",
  );
  assert.notEqual(byId.get("DUPLICATE_FUNDING").code, "FUNDING_REPLAYED");
});

async function sourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await sourceFiles(path)));
    } else if (entry.name.endsWith(".mjs")) {
      files.push(path);
    }
  }
  return files;
}

test("REORDERED and FUNDING_REPLAYED have no throw site anywhere in src/", async () => {
  const root = fileURLToPath(new URL("../src", import.meta.url));
  const carriers = { FUNDING_REPLAYED: [], REORDERED: [] };
  for (const path of await sourceFiles(root)) {
    const source = await readFile(path, "utf8");
    for (const code of Object.keys(carriers)) {
      if (source.includes(`"${code}"`)) {
        carriers[code].push(path.slice(root.length + 1));
      }
      // A thrown code always reaches fail()/terminalCode; a display map never does.
      assert.doesNotMatch(
        source,
        new RegExp(`(fail|terminalCode:|throw[^\\n]*)\\(?\\s*"${code}"`),
        `${path} appears to raise ${code}; the negative-check expectations must be updated`,
      );
    }
  }
  // The literals exist only as display labels. If that ever stops being true,
  // the reason vocabulary has grown and this test should be revisited.
  assert.deepEqual(carriers.REORDERED, [
    "monitor/control-plane/messages.mjs",
    "monitor/snapshot.mjs",
  ]);
  assert.deepEqual(carriers.FUNDING_REPLAYED, [
    "monitor/control-plane/messages.mjs",
    "monitor/snapshot.mjs",
  ]);
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
