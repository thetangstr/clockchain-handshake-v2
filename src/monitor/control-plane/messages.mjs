// src/monitor/control-plane/messages.mjs
//
// The operator control plane's message map. This is the ONLY module (besides
// src/core/verdict.mjs's emission site, src/core/evidence.mjs's ban pattern,
// the stakeholder message map, and test/**) allowed to contain the literal
// "AUTHORIZED" -- scripts/check-invariants.sh enforces that allowlist by exact
// file path. Nothing else in this control plane (routes.mjs, app.mjs,
// index.html, styles.css) may spell that literal.
//
// The rule this file exists to enforce: the word only ever comes out of
// renderVerdict(), and renderVerdict() only ever produces it when it is
// handed an object that looks exactly like the verifier's signed publication
// (verdict.mjs's VERDICT_SCHEMA shape: outcome === "AUTHORIZED" AND
// paymentMoved === false). Every other input -- null, undefined, a
// differently-shaped object, a guess made before the verifier has spoken --
// renders a pending or not-authorized message instead. That is what "pre-
// verdict AUTHORIZED absence" means and what the test file asserts.
//
// This dashboard is denser than the public stakeholder page (per spec, that
// is allowed here), so unlike the public page it is fine to show the raw
// reason code alongside the plain-language sentence -- this is the operator's
// own instrument, not audience-facing output.

export const STATUS_CODES = Object.freeze([
  "SESSION_STARTED",
  "REHEARSAL_PASSED",
  "TERMS_PUBLISHED",
  "REQUEST_SUBMITTED",
  "HANDSHAKE_REQUIRED",
  "IDENTITY_REGISTERED",
  "FUNDED",
  "PROPOSED",
  "ACCEPTED",
  "ACKNOWLEDGED",
  "EVIDENCE_RECEIVED",
  "VERIFYING",
]);

// The frozen public reason-code set (14 original + 2 rehearsal-gate additions,
// see docs/deviations.md D7). scripts/check-invariants.sh enforces this same
// set on the verifier/relay/role surfaces; this map exists so the operator
// dashboard never has to invent wording for a code live, mid-demo.
export const REASON_CODES = Object.freeze([
  "RENDEZVOUS_UNAVAILABLE",
  "EXPIRED",
  "MISSING",
  "DUPLICATE",
  "REORDERED",
  "MALFORMED",
  "AMBIGUOUS_WRITE",
  "BINDING_MISMATCH",
  "ANCHOR_UNVERIFIED",
  "ROLE_ALREADY_BOUND",
  "RATE_BLOCKED",
  "AMOUNT_UNRESOLVED",
  "FUNDING_REPLAYED",
  "FAILED",
  "REHEARSAL_NOT_AUTHORIZABLE",
  "REHEARSAL_SUBJECT_MISMATCH",
]);

export const STATUS_MESSAGES = Object.freeze({
  SESSION_STARTED: "Session started. No anchors exist yet; nothing can expire.",
  REHEARSAL_PASSED: "Rehearsal drill passed. Stakeholder engagement is cleared to begin.",
  TERMS_PUBLISHED: "The payer published the signed payment terms.",
  REQUEST_SUBMITTED: "The payment request was submitted for this session.",
  HANDSHAKE_REQUIRED: "Waiting on a role to bind and begin the handshake.",
  IDENTITY_REGISTERED: "Both on-chain identities are registered.",
  FUNDED: "Both session seats are funded for registration gas.",
  PROPOSED: "The proposal is anchored on Clockchain. The 10-minute window is open.",
  ACCEPTED: "The acceptance is anchored on Clockchain.",
  ACKNOWLEDGED: "The acknowledgment is anchored on Clockchain. All three anchors exist.",
  EVIDENCE_RECEIVED: "Both parties' signed evidence packages reached the relay.",
  VERIFYING: "The fresh, independent verifier is re-checking every anchor now.",
});

export const REASON_MESSAGES = Object.freeze({
  RENDEZVOUS_UNAVAILABLE: "The relay could not be reached before the window opened.",
  EXPIRED: "The 10-minute anchoring window closed before all three anchors landed.",
  MISSING: "An anchor this run needed was never written to Clockchain.",
  DUPLICATE: "More than one anchor was found where exactly one was expected.",
  REORDERED: "Anchors were found out of the required proposal -> acceptance -> acknowledgment sequence.",
  MALFORMED: "A party's evidence package did not match the required shape.",
  AMBIGUOUS_WRITE: "The signed amount could not be resolved to a single anchored proposal.",
  BINDING_MISMATCH: "A re-read anchor does not match the value this run originally recorded.",
  ANCHOR_UNVERIFIED: "An anchor could not be independently re-confirmed on-chain.",
  ROLE_ALREADY_BOUND: "A second agent tried to claim a role this session already bound.",
  RATE_BLOCKED: "Clockchain rate-limited this session's requests.",
  AMOUNT_UNRESOLVED: "The payment amount in the signed terms could not be resolved.",
  FUNDING_REPLAYED: "A funding transfer was refused as a replay of one already recorded.",
  FAILED: "This step failed. No further detail is safe to show without risking a leak.",
  REHEARSAL_NOT_AUTHORIZABLE: "A rehearsal sub-run reached the emission gate and was correctly refused.",
  REHEARSAL_SUBJECT_MISMATCH: "The verifier was asked to rehearsal-check a stakeholder run and refused.",
});

const FALLBACK_STATUS_MESSAGE =
  "Status update received. No money has moved.";
const FALLBACK_REASON_MESSAGE =
  "This run did not complete. No further detail is safe to show without risking a leak.";

/** Plain-language sentence for a run status code. Never throws on an unknown
 * code -- an operator dashboard must keep rendering through a code it does not
 * yet recognise rather than blank the screen mid-demo. */
export function statusMessage(code) {
  return STATUS_MESSAGES[code] ?? FALLBACK_STATUS_MESSAGE;
}

/** Plain-language sentence for a frozen reason code. Same never-throws rule
 * as statusMessage(). */
export function reasonMessage(code) {
  return REASON_MESSAGES[code] ?? FALLBACK_REASON_MESSAGE;
}

// The single spelling of the literal in this whole control plane. Kept as one
// module-private constant rather than repeated inline so a future reader
// grepping this file finds exactly one place the word is assembled.
const AUTHORIZED_OUTCOME = "AUTHORIZED";

function isSignedAuthorizedPublication(verdict) {
  return (
    verdict !== null &&
    typeof verdict === "object" &&
    !Array.isArray(verdict) &&
    verdict.outcome === AUTHORIZED_OUTCOME &&
    verdict.paymentMoved === false
  );
}

/**
 * Render the verdict panel from the snapshot's `verdict` field.
 *
 * `verdict` MUST be either null (no signed publication yet) or an object
 * shaped like verdict.mjs's published verdict (outcome, paymentMoved, and the
 * rest of VERDICT_KEYS). Anything else -- including a well-intentioned guess
 * assembled before the verifier has actually signed anything -- renders a
 * safe non-authorized message instead of the word. This is the enforcement
 * point the task's binding rule and the test file both refer to.
 */
export function renderVerdict(verdict) {
  if (verdict === null || verdict === undefined) {
    return Object.freeze({
      detail:
        "No money has moved. The independent verifier has not published a result yet.",
      headline: "Verdict pending",
      outcome: null,
      state: "pending",
    });
  }

  if (isSignedAuthorizedPublication(verdict)) {
    return Object.freeze({
      detail:
        "The independent verifier re-checked every anchor against Clockchain and signed this result. No money has moved.",
      headline: AUTHORIZED_OUTCOME,
      outcome: AUTHORIZED_OUTCOME,
      state: "authorized",
    });
  }

  const code =
    typeof verdict === "object" &&
    verdict !== null &&
    typeof verdict.outcome === "string" &&
    verdict.outcome !== AUTHORIZED_OUTCOME
      ? verdict.outcome
      : null;
  return Object.freeze({
    detail: code !== null ? reasonMessage(code) : FALLBACK_REASON_MESSAGE,
    headline: "Not authorized",
    outcome: code,
    state: "failed",
  });
}
