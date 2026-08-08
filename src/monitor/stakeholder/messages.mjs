// The stakeholder audience page's message map and pure view-model builder.
//
// This is the ONE file (besides src/core/verdict.mjs itself) allowed to spell
// the literal AUTHORIZED outcome word — scripts/check-invariants.sh allowlists
// it by name. It may do so only because it renders it FROM snapshot.verdict,
// which stays null until the verifier's signed publication exists; it must
// never assign or fabricate that field itself.
//
// Everything here is a pure function of (snapshot, nowMs) -> plain data. The
// DOM binding in app.mjs is a thin layer on top of this module so the view
// logic itself stays testable without a browser.

import {
  FAILED_STAGE,
  msSinceHeartbeat,
  msSinceUpdate,
  reasonSentence,
  ROLE_NAMES,
  STATUSES,
  stageSentence,
} from "../snapshot.mjs";

// The sentence that must appear in EVERY rendered state, including failure.
// It is the single most important line on the page.
export const NO_MONEY_MOVED_SENTENCE =
  "No money has moved. This is an authorization check only.";

// The five-step plain-English narration. Internal statuses fold into these
// five rows; a raw status code is never rendered. Grouping rationale:
//   - TERMS_PUBLISHED is preceded by session/rehearsal setup that has nothing
//     to show yet, so those fold into "not started" for step 1.
//   - PROPOSED is the anchored, on-the-record version of the same payment
//     request the requestor already submitted off-chain, so it completes
//     step 2 rather than opening a step of its own.
//   - HANDSHAKE_REQUIRED / IDENTITY_REGISTERED / FUNDED are pre-handshake
//     setup that happens around request submission; they fold into step 2 as
//     "still working on it" detail rather than getting their own row.
export const TIMELINE_STEPS = Object.freeze([
  Object.freeze({
    id: "terms_published",
    label: "Payer published the payment terms",
    statuses: Object.freeze([
      "SESSION_STARTED",
      "REHEARSAL_PASSED",
      "TERMS_PUBLISHED",
    ]),
    activeRole: "payer",
  }),
  Object.freeze({
    id: "request_submitted",
    label: "Requestor submitted a payment request",
    statuses: Object.freeze([
      "REQUEST_SUBMITTED",
      "HANDSHAKE_REQUIRED",
      "IDENTITY_REGISTERED",
      "FUNDED",
      "PROPOSED",
    ]),
    activeRole: "payee",
  }),
  Object.freeze({
    id: "accepted",
    label: "Requestor accepted the exact terms",
    statuses: Object.freeze(["ACCEPTED"]),
    activeRole: "payee",
  }),
  Object.freeze({
    id: "acknowledged",
    label: "Payer acknowledged",
    statuses: Object.freeze(["ACKNOWLEDGED"]),
    activeRole: "payer",
  }),
  Object.freeze({
    id: "verifying",
    label: "Clockchain — session host & independent checker.",
    statuses: Object.freeze(["EVIDENCE_RECEIVED", "VERIFYING"]),
    activeRole: "verifier",
  }),
]);

// Anchors correspond to timeline steps 2 (request-as-proposal), 3 (accepted),
// and 4 (acknowledged) — the three Clockchain receipts.
export const RECEIPT_CARDS = Object.freeze([
  Object.freeze({
    kind: "proposal",
    title: "Payment request recorded",
    stepId: "request_submitted",
  }),
  Object.freeze({
    kind: "acceptance",
    title: "Terms accepted",
    stepId: "accepted",
  }),
  Object.freeze({
    kind: "acknowledgment",
    title: "Acknowledgment recorded",
    stepId: "acknowledged",
  }),
]);

export const VERDICT_MESSAGES = Object.freeze({
  PENDING:
    "Waiting for the independent verifier's signed decision.",
  AUTHORIZED:
    "AUTHORIZED — the independent verifier confirmed the handshake. No money has moved.",
});

/** True if the union of every step's statuses is exactly STATUSES, with no
 * gaps and no duplicates. Used by tests to keep the timeline complete as the
 * status vocabulary evolves. */
export function timelineCoversAllStatuses() {
  const covered = TIMELINE_STEPS.flatMap((step) => step.statuses);
  const uniqueCovered = new Set(covered);
  if (uniqueCovered.size !== covered.length) return false;
  if (uniqueCovered.size !== STATUSES.length) return false;
  return STATUSES.every((status) => uniqueCovered.has(status));
}

function stepIndexForStatus(status) {
  return TIMELINE_STEPS.findIndex((step) => step.statuses.includes(status));
}

/** The last status actually reached, even if the run has since failed. */
export function lastProgressStatus(snapshot) {
  if (snapshot.currentStage !== FAILED_STAGE) {
    return snapshot.currentStage;
  }
  for (let i = snapshot.stageHistory.length - 1; i >= 0; i -= 1) {
    const entry = snapshot.stageHistory[i];
    if (STATUSES.includes(entry.status)) return entry.status;
  }
  return null;
}

/**
 * Build the view-model for the five-step timeline: one row per step with a
 * state of "done" | "active" | "failed" | "pending".
 */
export function buildTimelineView(snapshot) {
  const reached = lastProgressStatus(snapshot);
  const reachedIndex = reached === null ? -1 : stepIndexForStatus(reached);
  const failed = snapshot.currentStage === FAILED_STAGE;
  const decided = snapshot.verdict !== null && snapshot.verdict !== undefined;

  // A step finishes only once its LAST status is reached. Grouping several
  // statuses under one row means the earlier ones are that row still in
  // progress: SESSION_STARTED is not "the payer published the terms", and a run
  // that has only just opened must show nothing finished at all -- a green row
  // for something that has not happened is the one thing an evidence demo
  // cannot afford on a projector.
  //
  // The last step is the exception, in the other direction: VERIFYING is where
  // a snapshot rests while the checker works, so that row finishes on the
  // verdict and never before it.
  const lastStepIndex = TIMELINE_STEPS.length - 1;
  const finishedItsStep =
    reachedIndex !== -1 &&
    reachedIndex !== lastStepIndex &&
    reached === TIMELINE_STEPS[reachedIndex].statuses[
      TIMELINE_STEPS[reachedIndex].statuses.length - 1
    ];
  const activeIndex = finishedItsStep
    ? reachedIndex + 1
    : reachedIndex === -1
      ? 0
      : reachedIndex;

  return TIMELINE_STEPS.map((step, index) => {
    let state;
    if (decided) {
      state = "done";
    } else if (failed) {
      state = index < reachedIndex ? "done" : index === reachedIndex ? "failed" : "pending";
    } else if (index < activeIndex) {
      state = "done";
    } else if (index === activeIndex) {
      state = "active";
    } else {
      state = "pending";
    }
    return Object.freeze({
      id: step.id,
      label: step.label,
      state,
    });
  });
}

/**
 * Build the "still working" freshness line for the step currently in
 * progress, driven by that step's active role's heartbeat. Returns null when
 * no step is actively in progress (finished or failed).
 */
export function buildFreshnessView(snapshot, nowMs) {
  const activeStep = buildTimelineView(snapshot).find(
    (row) => row.state === "active",
  );
  if (!activeStep) return null;
  const stepDef = TIMELINE_STEPS.find((step) => step.id === activeStep.id);
  const heartbeatEntry = snapshot.heartbeat[stepDef.activeRole];
  const sinceMs = msSinceHeartbeat(heartbeatEntry, nowMs);
  if (sinceMs === null) {
    return "Still working — waiting for the first update.";
  }
  const seconds = Math.floor(sinceMs / 1000);
  return `Still working — last update ${seconds} second${seconds === 1 ? "" : "s"} ago.`;
}

/** True if the whole snapshot itself looks stale (relay stopped refreshing
 * it), independent of any one role's heartbeat. */
export function isSnapshotStale(snapshot, nowMs, staleAfterMs) {
  return msSinceUpdate(snapshot, nowMs) > staleAfterMs;
}

/**
 * Build the verdict-area view-model. Renders ONLY from snapshot.verdict: null
 * means pending regardless of currentStage, including while FAILED — a
 * failed run never fabricates a verdict, it simply never gets one.
 */
export function buildVerdictView(snapshot) {
  if (snapshot.verdict === null) {
    return Object.freeze({ state: "pending", sentence: VERDICT_MESSAGES.PENDING });
  }
  const sentence =
    VERDICT_MESSAGES[snapshot.verdict.outcome] ?? VERDICT_MESSAGES.AUTHORIZED;
  return Object.freeze({ state: "published", sentence });
}

/** Build the failure banner view-model, or null if the run has not failed. */
export function buildFailureView(snapshot) {
  if (snapshot.currentStage !== FAILED_STAGE) return null;
  return Object.freeze({
    sentence: reasonSentence(snapshot),
    noMoneyMoved: NO_MONEY_MOVED_SENTENCE,
  });
}

/**
 * Build the complete stakeholder view-model for a snapshot at a point in
 * time. Every branch includes noMoneyMoved — that line must never be
 * skippable, in any state.
 */
export function buildStakeholderView(snapshot, nowMs) {
  return Object.freeze({
    currentStatusSentence: stageSentence(snapshot),
    failure: buildFailureView(snapshot),
    freshness: buildFreshnessView(snapshot, nowMs),
    heartbeat: Object.fromEntries(
      ROLE_NAMES.map((role) => [
        role,
        msSinceHeartbeat(snapshot.heartbeat[role], nowMs),
      ]),
    ),
    noMoneyMoved: NO_MONEY_MOVED_SENTENCE,
    sessionId: snapshot.sessionId,
    timeline: buildTimelineView(snapshot),
    verdict: buildVerdictView(snapshot),
  });
}
