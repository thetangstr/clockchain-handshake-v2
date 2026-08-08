import assert from "node:assert/strict";
import test from "node:test";

import {
  buildFreshnessView,
  buildTimelineView,
  deriveProgressFacts,
  TIMELINE_STEPS,
} from "../src/monitor/stakeholder/messages.mjs";

function snapshotAt(currentStage, extra = {}) {
  return {
    anchors: { acceptance: null, acknowledgment: null, proposal: null },
    currentStage,
    funding: null,
    heartbeat: { payee: null, payer: null, verifier: null },
    identities: null,
    paymentMoved: false,
    reasonCode: null,
    sessionId: "00000000-0000-4000-8000-000000000000",
    stageHistory: [{ atMs: 1, status: currentStage }],
    verdict: null,
    ...extra,
  };
}

function history(...statuses) {
  return statuses.map((status, index) => ({ atMs: index + 1, status }));
}

function states(snapshot) {
  return buildTimelineView(snapshot).map((row) => row.state);
}

test("funding and identity readiness never fabricate business progress", () => {
  for (const stage of ["FUNDED", "IDENTITY_REGISTERED"]) {
    const snapshot = snapshotAt(stage, {
      funding: { atMs: 1, funded: true },
      identities: {
        payer: { address: `0x${"1".repeat(40)}`, agentId: "1" },
        payee: { address: `0x${"2".repeat(40)}`, agentId: "2" },
      },
    });
    assert.deepEqual(states(snapshot), [
      "active",
      "pending",
      "pending",
      "pending",
      "pending",
    ]);
    assert.equal(deriveProgressFacts(snapshot).termsPublished, false);
  }
});

test("terms and request rows complete only from their exact history entries", () => {
  const terms = snapshotAt("FUNDED", {
    stageHistory: history("SESSION_STARTED", "TERMS_PUBLISHED", "FUNDED"),
  });
  assert.deepEqual(states(terms), [
    "done",
    "active",
    "pending",
    "pending",
    "pending",
  ]);

  const request = snapshotAt("HANDSHAKE_REQUIRED", {
    stageHistory: history(
      "SESSION_STARTED",
      "TERMS_PUBLISHED",
      "REQUEST_SUBMITTED",
      "HANDSHAKE_REQUIRED",
    ),
  });
  assert.deepEqual(states(request), [
    "done",
    "done",
    "active",
    "pending",
    "pending",
  ]);
});

test("the three receipt facts remain independent of status order and one another", () => {
  const base = {
    stageHistory: history("SESSION_STARTED", "TERMS_PUBLISHED", "REQUEST_SUBMITTED"),
  };

  const proposalOnly = snapshotAt("REQUEST_SUBMITTED", {
    ...base,
    anchors: { proposal: {}, acceptance: null, acknowledgment: null },
  });
  assert.equal(deriveProgressFacts(proposalOnly).proposalRecorded, true);
  assert.deepEqual(states(proposalOnly), [
    "done",
    "done",
    "active",
    "pending",
    "pending",
  ]);

  const acceptanceOnly = snapshotAt("REQUEST_SUBMITTED", {
    ...base,
    anchors: { proposal: null, acceptance: {}, acknowledgment: null },
  });
  assert.deepEqual(states(acceptanceOnly), [
    "done",
    "done",
    "done",
    "active",
    "pending",
  ]);

  const acknowledgmentOnly = snapshotAt("REQUEST_SUBMITTED", {
    ...base,
    anchors: { proposal: null, acceptance: null, acknowledgment: {} },
  });
  assert.deepEqual(states(acknowledgmentOnly), [
    "done",
    "done",
    "active",
    "done",
    "pending",
  ]);
});

test("evidence and verification activate only the checker and never invent a verdict", () => {
  for (const stage of ["EVIDENCE_RECEIVED", "VERIFYING"]) {
    const snapshot = snapshotAt(stage);
    assert.deepEqual(states(snapshot), [
      "pending",
      "pending",
      "pending",
      "pending",
      "active",
    ]);
    assert.equal(deriveProgressFacts(snapshot).verdictPublished, false);
  }
});

test("a verdict completes only the checker and never backfills absent artifacts", () => {
  const decided = snapshotAt("VERIFYING", {
    verdict: { outcome: "AUTHORIZED", paymentMoved: false },
  });
  assert.deepEqual(states(decided), [
    "active",
    "pending",
    "pending",
    "pending",
    "done",
  ]);
});

test("a P4-shaped bouncing history completes every row from its actual facts", () => {
  const snapshot = snapshotAt("VERIFYING", {
    anchors: { proposal: {}, acceptance: {}, acknowledgment: {} },
    funding: { atMs: 2, funded: true },
    identities: {
      payer: { address: `0x${"1".repeat(40)}`, agentId: "9447" },
      payee: { address: `0x${"2".repeat(40)}`, agentId: "9448" },
    },
    stageHistory: history(
      "SESSION_STARTED",
      "FUNDED",
      "REQUEST_SUBMITTED",
      "IDENTITY_REGISTERED",
      "TERMS_PUBLISHED",
      "REQUEST_SUBMITTED",
      "ACCEPTED",
      "ACKNOWLEDGED",
      "EVIDENCE_RECEIVED",
      "VERIFYING",
    ),
    verdict: { outcome: "AUTHORIZED", paymentMoved: false },
  });
  assert.deepEqual(states(snapshot), ["done", "done", "done", "done", "done"]);
});

test("a failure marks the first fact-incomplete row while preserving completed facts", () => {
  const failed = snapshotAt("FAILED", {
    anchors: { proposal: {}, acceptance: null, acknowledgment: {} },
    reasonCode: "EXPIRED",
    stageHistory: history(
      "SESSION_STARTED",
      "TERMS_PUBLISHED",
      "REQUEST_SUBMITTED",
      "FAILED",
    ),
  });
  assert.deepEqual(states(failed), [
    "done",
    "done",
    "failed",
    "done",
    "pending",
  ]);
});

test("funding and identity facts drive the existing visible readiness line", () => {
  const base = snapshotAt("SESSION_STARTED");
  assert.match(buildFreshnessView(base, 10), /joining with fresh local keys/i);

  const funded = snapshotAt("SESSION_STARTED", {
    funding: { atMs: 2, funded: true },
  });
  assert.match(buildFreshnessView(funded, 10), /registering identities/i);

  const ready = snapshotAt("SESSION_STARTED", {
    funding: { atMs: 2, funded: true },
    identities: {
      payer: { address: `0x${"1".repeat(40)}`, agentId: "1" },
      payee: { address: `0x${"2".repeat(40)}`, agentId: "2" },
    },
  });
  assert.match(buildFreshnessView(ready, 10), /both independent agents are ready/i);
});

test("the public timeline stays five stable rows without enum ownership metadata", () => {
  assert.deepEqual(
    TIMELINE_STEPS.map(({ id }) => id),
    [
      "terms_published",
      "request_submitted",
      "accepted",
      "acknowledged",
      "verifying",
    ],
  );
  assert.equal(TIMELINE_STEPS.every((step) => !("statuses" in step)), true);
});
