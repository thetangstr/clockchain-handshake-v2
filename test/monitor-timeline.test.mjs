// The five-step timeline is what an audience actually reads off the projector,
// and until now nothing pinned when a row turns green. That gap let a run that
// had only just opened render "the payer published the payment terms" as
// finished, because SESSION_STARTED shares a row with TERMS_PUBLISHED and any
// status in the row was treated as completing it. On a demo whose entire claim
// is "we only assert what we can prove", a row claiming something that has not
// happened is the worst available bug.
import assert from "node:assert/strict";
import test from "node:test";

import { TIMELINE_STEPS, buildTimelineView } from "../src/monitor/stakeholder/messages.mjs";

function snapshotAt(currentStage, extra = {}) {
  return {
    anchors: { acceptance: null, acknowledgment: null, proposal: null },
    currentStage,
    heartbeat: { payee: null, payer: null, verifier: null },
    paymentMoved: false,
    reasonCode: null,
    sessionId: "00000000-0000-4000-8000-000000000000",
    stageHistory: [{ atMs: 1, status: currentStage }],
    verdict: null,
    ...extra,
  };
}

function states(snapshot) {
  return buildTimelineView(snapshot).map((row) => row.state);
}

test("a run that has only just opened shows nothing finished", () => {
  assert.deepEqual(states(snapshotAt("SESSION_STARTED")), [
    "active",
    "pending",
    "pending",
    "pending",
    "pending",
  ]);
});

test("a row finishes on the last status in that row, not the first", () => {
  // Terms published is the end of row 1, so row 1 finishes and row 2 opens.
  assert.deepEqual(states(snapshotAt("TERMS_PUBLISHED")), [
    "done",
    "active",
    "pending",
    "pending",
    "pending",
  ]);
  // Everything between REQUEST_SUBMITTED and PROPOSED is row 2 still working.
  for (const midway of ["REQUEST_SUBMITTED", "HANDSHAKE_REQUIRED", "IDENTITY_REGISTERED", "FUNDED"]) {
    assert.deepEqual(
      states(snapshotAt(midway)),
      ["done", "active", "pending", "pending", "pending"],
      `${midway} is row 2 in progress, not row 2 finished`,
    );
  }
  assert.deepEqual(states(snapshotAt("PROPOSED")), [
    "done",
    "done",
    "active",
    "pending",
    "pending",
  ]);
});

test("the checker's row never finishes before the verdict does", () => {
  for (const stage of ["EVIDENCE_RECEIVED", "VERIFYING"]) {
    const rows = states(snapshotAt(stage));
    assert.equal(
      rows[rows.length - 1],
      "active",
      `${stage} must leave the checker's row in progress: it has not decided yet`,
    );
  }

  const decided = snapshotAt("VERIFYING", {
    verdict: { outcome: "AUTHORIZED", paymentMoved: false },
  });
  assert.deepEqual(states(decided), ["done", "done", "done", "done", "done"]);
});

test("exactly one row is active until the run ends", () => {
  for (const step of TIMELINE_STEPS) {
    for (const status of step.statuses) {
      const active = states(snapshotAt(status)).filter((s) => s === "active");
      assert.equal(active.length, 1, `${status} must leave exactly one row in progress`);
    }
  }
});

test("a failure marks the row it stopped on and claims nothing after it", () => {
  const failed = snapshotAt("FAILED", {
    reasonCode: "EXPIRED",
    stageHistory: [
      { atMs: 1, status: "SESSION_STARTED" },
      { atMs: 2, status: "TERMS_PUBLISHED" },
      { atMs: 3, status: "PROPOSED" },
    ],
  });
  assert.deepEqual(states(failed), ["done", "failed", "pending", "pending", "pending"]);
});
