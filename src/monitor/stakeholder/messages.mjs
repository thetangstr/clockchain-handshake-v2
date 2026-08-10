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
  stageSentence,
} from "../snapshot.mjs";

// The sentence that must appear in EVERY rendered state, including failure.
// It is the single most important line on the page.
export const NO_MONEY_MOVED_SENTENCE =
  "No money has moved. This is an authorization check only.";

// The five-step plain-English narration. These are display rows, not ownership
// buckets for the wire-status enum. Completion is derived below from the exact
// artifact named by each row; setup statuses never turn a business claim green.
export const TIMELINE_STEPS = Object.freeze([
  Object.freeze({
    id: "terms_published",
    label: "Payer published the payment terms",
    activeRole: "payer",
  }),
  Object.freeze({
    id: "request_submitted",
    label: "Requestor submitted a payment request",
    activeRole: "payee",
  }),
  Object.freeze({
    id: "accepted",
    label: "Requestor accepted the exact terms",
    activeRole: "payee",
  }),
  Object.freeze({
    id: "acknowledged",
    label: "Payer acknowledged",
    activeRole: "payer",
  }),
  Object.freeze({
    id: "verifying",
    label: "Clockchain — session host & independent checker.",
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
    "Waiting for the independent checker's signed decision.",
  AUTHORIZED:
    "AUTHORIZED — the independent checker confirmed the handshake. No money has moved.",
});

function hasStage(snapshot, status) {
  return snapshot.currentStage === status || snapshot.stageHistory.some(
    (entry) => entry.status === status,
  );
}

/** Exact facts used by the projector. Later facts deliberately do not imply
 * earlier ones: a verdict cannot create a missing receipt, and readiness
 * fields cannot create a mandate or payment request. */
export function deriveProgressFacts(snapshot) {
  return Object.freeze({
    termsPublished: hasStage(snapshot, "TERMS_PUBLISHED"),
    requestSubmitted: hasStage(snapshot, "REQUEST_SUBMITTED"),
    fundingReady: snapshot.funding?.funded === true,
    identitiesReady:
      snapshot.identities?.payer != null && snapshot.identities?.payee != null,
    proposalRecorded: snapshot.anchors?.proposal != null,
    acceptanceRecorded: snapshot.anchors?.acceptance != null,
    acknowledgmentRecorded: snapshot.anchors?.acknowledgment != null,
    evidenceReceived: hasStage(snapshot, "EVIDENCE_RECEIVED"),
    verificationStarted: hasStage(snapshot, "VERIFYING"),
    verdictPublished: snapshot.verdict != null,
  });
}

/**
 * Build the view-model for the five-step timeline: one row per step with a
 * state of "done" | "active" | "failed" | "pending".
 */
export function buildTimelineView(snapshot) {
  const facts = deriveProgressFacts(snapshot);
  const failed = snapshot.currentStage === FAILED_STAGE;
  const completed = [
    facts.termsPublished,
    facts.requestSubmitted,
    facts.acceptanceRecorded,
    facts.acknowledgmentRecorded,
    facts.verdictPublished,
  ];
  const firstIncomplete = completed.findIndex((complete) => !complete);
  const checkerIsWorking =
    !facts.verdictPublished &&
    (facts.evidenceReceived || facts.verificationStarted);
  const activeIndex = checkerIsWorking && !failed
    ? TIMELINE_STEPS.length - 1
    : firstIncomplete;

  return TIMELINE_STEPS.map((step, index) => {
    let state;
    if (completed[index]) {
      state = "done";
    } else if (failed) {
      state = index === activeIndex ? "failed" : "pending";
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
  const facts = deriveProgressFacts(snapshot);
  const activeStep = buildTimelineView(snapshot).find(
    (row) => row.state === "active",
  );
  if (!activeStep) return null;
  if (activeStep.id === "terms_published") {
    if (!facts.fundingReady) {
      return "Payer and Requestor are joining with fresh local keys.";
    }
    if (!facts.identitiesReady) {
      return "Both seats are funded — the independent agents are registering identities.";
    }
    return "Both independent agents are ready — waiting for the Payer's signed terms.";
  }
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
