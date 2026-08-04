import assert from "node:assert/strict";
import test from "node:test";

import {
  ANCHOR_KINDS,
  buildSnapshot,
  FAILED_STAGE,
  REASON_CODES,
  REASON_MESSAGES,
  ROLE_NAMES,
  SNAPSHOT_SCHEMA,
  SnapshotValidationError,
  STATUSES,
  STATUS_MESSAGES,
  messageMapsAreComplete,
  validateSnapshot,
} from "../src/monitor/snapshot.mjs";
import {
  buildFailureView,
  buildStakeholderView,
  buildVerdictView,
  NO_MONEY_MOVED_SENTENCE,
  timelineCoversAllStatuses,
  VERDICT_MESSAGES,
} from "../src/monitor/stakeholder/messages.mjs";

const LEDGER_ID_1 = "11111111-1111-4111-8111-111111111111";
const LEDGER_ID_2 = "22222222-2222-4222-8222-222222222222";
const LEDGER_ID_3 = "33333333-3333-4333-8333-333333333333";

function anchor(kind, ledgerId, blockHeight) {
  return {
    blockHeight,
    blockTime: 1_700_000_000_000,
    explorerUrl: `https://explorer.example/block/${blockHeight}`,
    kind,
    ledgerId,
    receipt: { kind, ledgerId, signed: true },
    signedBy: { address: "0x" + "b".repeat(40), agentId: "9001" },
    terms: {
      currency: "USD",
      expirySeconds: "600",
      predecessor: kind === "proposal" ? null : "2731906",
      sequence: kind === "proposal" ? "1" : kind === "acceptance" ? "2" : "3",
      sessionDigest: "d".repeat(64),
      value: "100",
    },
  };
}

function makeSnapshot(overrides = {}) {
  const base = {
    anchors: {
      acceptance: null,
      acknowledgment: null,
      proposal: null,
    },
    currentStage: "VERIFYING",
    funding: { atMs: 1_700_000_000_000, funded: true },
    heartbeat: {
      payee: { lastSeenMs: 1_700_000_005_000 },
      payer: { lastSeenMs: 1_700_000_005_000 },
      verifier: { lastSeenMs: 1_700_000_006_000 },
    },
    reasonCode: null,
    sessionId: "session-abc",
    stageHistory: [
      { atMs: 1_700_000_000_000, status: "SESSION_STARTED" },
      { atMs: 1_700_000_001_000, status: "TERMS_PUBLISHED" },
      { atMs: 1_700_000_002_000, status: "REQUEST_SUBMITTED" },
      { atMs: 1_700_000_003_000, status: "PROPOSED" },
      { atMs: 1_700_000_004_000, status: "ACCEPTED" },
      { atMs: 1_700_000_004_500, status: "ACKNOWLEDGED" },
      { atMs: 1_700_000_005_000, status: "EVIDENCE_RECEIVED" },
      { atMs: 1_700_000_006_000, status: "VERIFYING" },
    ],
    subjectRun: "stakeholder",
    updatedAtMs: 1_700_000_006_000,
    verdict: null,
  };
  return buildSnapshot({ ...base, ...overrides });
}

// Like makeSnapshot, but skips buildSnapshot's own validation — for
// constructing deliberately-broken fixtures that validateSnapshot itself is
// expected to reject. makeSnapshot would throw while building the fixture,
// before the test even reaches its assert.throws.
function rawSnapshot(overrides = {}) {
  const valid = makeSnapshot();
  return {
    schema: SNAPSHOT_SCHEMA,
    ...valid,
    ...overrides,
  };
}

test("message maps cover every status and every reason code", () => {
  assert.equal(messageMapsAreComplete(), true);

  for (const status of STATUSES) {
    assert.equal(typeof STATUS_MESSAGES[status], "string");
    assert.ok(STATUS_MESSAGES[status].length > 0, `missing message for ${status}`);
  }
  assert.equal(typeof STATUS_MESSAGES[FAILED_STAGE], "string");
  assert.ok(STATUS_MESSAGES[FAILED_STAGE].length > 0);

  for (const code of REASON_CODES) {
    assert.equal(typeof REASON_MESSAGES[code], "string");
    assert.ok(REASON_MESSAGES[code].length > 0, `missing message for ${code}`);
  }

  // No raw status/reason code text leaks into its own sentence (a crude
  // guard against "explain a code with the code").
  for (const status of STATUSES) {
    assert.ok(!STATUS_MESSAGES[status].includes(status));
  }
  for (const code of REASON_CODES) {
    assert.ok(!REASON_MESSAGES[code].includes(code));
  }

  // Bidirectional completeness: the maps carry exactly the frozen keys, no
  // extra, no missing.
  assert.deepEqual(
    Object.keys(STATUS_MESSAGES).sort(),
    [...STATUSES, FAILED_STAGE].sort(),
  );
  assert.deepEqual(Object.keys(REASON_MESSAGES).sort(), [...REASON_CODES].sort());
});

test("the five-step timeline covers every status exactly once", () => {
  assert.equal(timelineCoversAllStatuses(), true);
});

test("buildSnapshot produces a snapshot that validates cleanly", () => {
  const snapshot = makeSnapshot();
  assert.equal(validateSnapshot(snapshot), true);
  assert.equal(snapshot.schema, SNAPSHOT_SCHEMA);
  assert.equal(snapshot.paymentMoved, false);
  assert.equal(snapshot.verdict, null);
  assert.equal(snapshot.reasonCode, null);
});

test("a snapshot with all three anchors populated validates", () => {
  const snapshot = makeSnapshot({
    anchors: {
      acceptance: anchor("acceptance", LEDGER_ID_2, "1002"),
      acknowledgment: anchor("acknowledgment", LEDGER_ID_3, "1003"),
      proposal: anchor("proposal", LEDGER_ID_1, "1001"),
    },
  });
  assert.equal(validateSnapshot(snapshot), true);
  for (const kind of ANCHOR_KINDS) {
    assert.equal(snapshot.anchors[kind].kind, kind);
  }
});

test("validateSnapshot rejects a snapshot missing a top-level key", () => {
  const snapshot = makeSnapshot();
  const { verdict: _drop, ...broken } = snapshot;
  assert.throws(() => validateSnapshot(broken), SnapshotValidationError);
});

test("validateSnapshot rejects the wrong schema string", () => {
  assert.throws(
    () => validateSnapshot({ ...makeSnapshot(), schema: "wrong/v1" }),
    SnapshotValidationError,
  );
});

test("validateSnapshot rejects a reasonCode present while not FAILED", () => {
  assert.throws(
    () =>
      validateSnapshot({
        ...makeSnapshot(),
        reasonCode: "EXPIRED",
      }),
    SnapshotValidationError,
  );
});

test("validateSnapshot rejects FAILED without a frozen reasonCode", () => {
  assert.throws(
    () =>
      validateSnapshot({
        ...makeSnapshot(),
        currentStage: FAILED_STAGE,
        reasonCode: null,
        stageHistory: [
          ...makeSnapshot().stageHistory,
          { atMs: 1_700_000_007_000, status: FAILED_STAGE },
        ],
      }),
    SnapshotValidationError,
  );
});

test("validateSnapshot rejects an unregistered reasonCode", () => {
  assert.throws(
    () =>
      validateSnapshot({
        ...makeSnapshot(),
        currentStage: FAILED_STAGE,
        reasonCode: "NOT_A_REAL_CODE",
        stageHistory: [
          ...makeSnapshot().stageHistory,
          { atMs: 1_700_000_007_000, status: FAILED_STAGE },
        ],
      }),
    SnapshotValidationError,
  );
});

test("validateSnapshot rejects out-of-order stageHistory", () => {
  const snapshot = makeSnapshot();
  const shuffled = [...snapshot.stageHistory];
  [shuffled[0], shuffled[1]] = [shuffled[1], shuffled[0]];
  assert.throws(
    () => validateSnapshot({ ...snapshot, stageHistory: shuffled }),
    SnapshotValidationError,
  );
});

test("validateSnapshot rejects a stageHistory tail that disagrees with currentStage", () => {
  const snapshot = makeSnapshot();
  assert.throws(
    () =>
      validateSnapshot({
        ...snapshot,
        stageHistory: snapshot.stageHistory.slice(0, -1),
      }),
    SnapshotValidationError,
  );
});

test("validateSnapshot rejects an anchor whose kind does not match its slot", () => {
  const snapshot = rawSnapshot({
    anchors: {
      acceptance: null,
      acknowledgment: null,
      proposal: anchor("acceptance", LEDGER_ID_1, "1001"),
    },
  });
  assert.throws(() => validateSnapshot(snapshot), SnapshotValidationError);
});

test("validateSnapshot rejects a malformed ledgerId", () => {
  const badAnchor = anchor("proposal", "not-a-uuid", "1001");
  const snapshot = rawSnapshot({
    anchors: { acceptance: null, acknowledgment: null, proposal: badAnchor },
  });
  assert.throws(() => validateSnapshot(snapshot), SnapshotValidationError);
});

test("validateSnapshot rejects heartbeat missing a role", () => {
  const snapshot = makeSnapshot();
  const { verifier: _drop, ...brokenHeartbeat } = snapshot.heartbeat;
  assert.throws(
    () => validateSnapshot({ ...snapshot, heartbeat: brokenHeartbeat }),
    SnapshotValidationError,
  );
});

test("validateSnapshot rejects paymentMoved: true outright", () => {
  const snapshot = makeSnapshot();
  assert.throws(
    () => validateSnapshot({ ...snapshot, paymentMoved: true }),
    SnapshotValidationError,
  );
});

test("validateSnapshot rejects a verdict with paymentMoved: true", () => {
  const snapshot = rawSnapshot({
    currentStage: "VERIFYING",
    verdict: { outcome: "AUTHORIZED", paymentMoved: true },
  });
  assert.throws(() => validateSnapshot(snapshot), SnapshotValidationError);
});

test("validateSnapshot rejects a published verdict on a rehearsal run", () => {
  assert.throws(
    () =>
      validateSnapshot(
        rawSnapshot({
          subjectRun: "rehearsal",
          verdict: { outcome: "AUTHORIZED", paymentMoved: false },
        }),
      ),
    SnapshotValidationError,
  );
});

test("verdict stays null until the verifier's signed publication exists", () => {
  const stillRunning = makeSnapshot({ verdict: null });
  const view = buildVerdictView(stillRunning);
  assert.equal(view.state, "pending");
  assert.equal(view.sentence, VERDICT_MESSAGES.PENDING);
  assert.ok(!view.sentence.includes("AUTHORIZED"));

  const failedButStillNoVerdict = makeSnapshot({
    currentStage: FAILED_STAGE,
    reasonCode: "EXPIRED",
    stageHistory: [
      ...makeSnapshot().stageHistory,
      { atMs: 1_700_000_007_000, status: FAILED_STAGE },
    ],
    verdict: null,
  });
  const failedView = buildVerdictView(failedButStillNoVerdict);
  assert.equal(failedView.state, "pending");
  assert.ok(!failedView.sentence.includes("AUTHORIZED"));

  const published = makeSnapshot({
    verdict: { outcome: "AUTHORIZED", paymentMoved: false },
  });
  const publishedView = buildVerdictView(published);
  assert.equal(publishedView.state, "published");
  assert.ok(publishedView.sentence.includes("AUTHORIZED"));
});

test("paymentMoved:false / no-money-moved sentence is present in every rendered state", () => {
  const inProgress = makeSnapshot();
  const failed = makeSnapshot({
    currentStage: FAILED_STAGE,
    reasonCode: "BINDING_MISMATCH",
    stageHistory: [
      ...makeSnapshot().stageHistory,
      { atMs: 1_700_000_007_000, status: FAILED_STAGE },
    ],
  });
  const published = makeSnapshot({
    verdict: { outcome: "AUTHORIZED", paymentMoved: false },
  });

  for (const snapshot of [inProgress, failed, published]) {
    assert.equal(snapshot.paymentMoved, false);
    const view = buildStakeholderView(snapshot, snapshot.updatedAtMs);
    assert.equal(view.noMoneyMoved, NO_MONEY_MOVED_SENTENCE);
    assert.ok(view.noMoneyMoved.length > 0);
  }

  const failureView = buildFailureView(failed);
  assert.equal(failureView.noMoneyMoved, NO_MONEY_MOVED_SENTENCE);
  assert.ok(failureView.sentence.length > 0);
  assert.ok(!failureView.sentence.includes("BINDING_MISMATCH"));
});

test("every frozen reason code renders a first-class, non-code failure sentence", () => {
  for (const code of REASON_CODES) {
    const snapshot = makeSnapshot({
      currentStage: FAILED_STAGE,
      reasonCode: code,
      stageHistory: [
        ...makeSnapshot().stageHistory,
        { atMs: 1_700_000_007_000, status: FAILED_STAGE },
      ],
    });
    const view = buildFailureView(snapshot);
    assert.ok(view.sentence.length > 0, `no sentence for ${code}`);
    assert.equal(view.noMoneyMoved, NO_MONEY_MOVED_SENTENCE);
  }
});

test("heartbeat entries may be null (role not yet connected)", () => {
  const snapshot = makeSnapshot({
    heartbeat: {
      payee: { lastSeenMs: 1_700_000_005_000 },
      payer: { lastSeenMs: 1_700_000_005_000 },
      verifier: null,
    },
  });
  assert.equal(validateSnapshot(snapshot), true);
  for (const role of ROLE_NAMES) {
    assert.ok(role in snapshot.heartbeat);
  }
});

test("the full stakeholder view never leaks a raw status or reason code as its headline sentence", () => {
  for (const status of STATUSES) {
    const snapshot = makeSnapshot({
      currentStage: status,
      stageHistory: [{ atMs: 1_700_000_000_000, status }],
    });
    const view = buildStakeholderView(snapshot, snapshot.updatedAtMs);
    assert.notEqual(view.currentStatusSentence, status);
    assert.ok(view.currentStatusSentence.length > 0);
  }
});
