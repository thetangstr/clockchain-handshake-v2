// The single source both monitor views (stakeholder audience page, and any
// later control-plane/operator view) render from. GET /v1/sessions/{sid}/snapshot
// on the relay returns a value shaped exactly like this. Nothing downstream may
// invent a shape of its own — build it once, correctly, here.
//
// This module is intentionally display-agnostic: it defines the wire shape,
// validates it structurally, and maps every status/reason code onto a plain
// English sentence. It does NOT decide how a page groups those statuses into
// a shorter narrated timeline — that is a view concern and lives with the
// view (see src/monitor/stakeholder/messages.mjs).
//
// paymentMoved is always false in this system; no code path here ever sets it
// to true. The verdict field is null until the verifier's SIGNED publication
// exists — nothing in this file may assign it any other way, and this file
// deliberately never spells the literal outcome word: that string is
// allowlisted only at its one emission site (src/core/verdict.mjs) and at the
// stakeholder message map (src/monitor/stakeholder/messages.mjs), not here.

export const SNAPSHOT_SCHEMA = "clockchain.handshake-snapshot/v1";

// The whole run, in order. This is the INTERNAL vocabulary — a raw member of
// this list must never be shown to a viewer; STATUS_MESSAGES exists so no
// caller has an excuse to skip translating it.
export const STATUSES = Object.freeze([
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

// The one terminal, non-progress stage. A snapshot's currentStage is either a
// member of STATUSES (still moving forward) or exactly this sentinel (stopped
// for good, short of the signed verdict). It is intentionally NOT a member of
// STATUSES: the run either advances through the vocabulary above, or it stops.
export const FAILED_STAGE = "FAILED";

// Frozen public failure-reason vocabulary. Anything outside this set is a bug,
// not a new reason a viewer should ever see.
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

// The three anchored transitions of the bilateral handshake. Kind strings
// match the "kind" values already used for these transitions elsewhere in the
// core protocol modules (see src/core/messages.mjs).
export const ANCHOR_KINDS = Object.freeze([
  "proposal",
  "acceptance",
  "acknowledgment",
]);

// Per-role heartbeat. "verifier" only starts reporting once evidence review
// begins; it is null in the snapshot until then.
export const ROLE_NAMES = Object.freeze(["payer", "payee", "verifier"]);

export const SNAPSHOT_KEYS = Object.freeze([
  "anchors",
  "currentStage",
  "funding",
  "heartbeat",
  "identities",
  "paymentMoved",
  "reasonCode",
  "schema",
  "sessionId",
  "stageHistory",
  "subjectRun",
  "updatedAtMs",
  "verdict",
]);

export const ANCHOR_KEYS = Object.freeze([
  "blockHeight",
  "blockTime",
  "explorerUrl",
  "kind",
  "ledgerId",
  "receipt",
  "signedBy",
  "terms",
]);

// What the signed transition actually said, carried through so a viewer can read
// the receipt rather than take our word for what it contained. Every field here
// is lifted verbatim out of the bytes that were signed and anchored -- none of
// it is computed, and none of it may be added to by a display layer.
export const TERMS_KEYS = Object.freeze([
  "currency",
  "expirySeconds",
  "predecessor",
  "sequence",
  "sessionDigest",
  "value",
]);

export const SIGNED_BY_KEYS = Object.freeze(["address", "agentId"]);

export const STAGE_HISTORY_ENTRY_KEYS = Object.freeze(["atMs", "status"]);

export const HEARTBEAT_ENTRY_KEYS = Object.freeze(["lastSeenMs"]);

export const FUNDING_KEYS = Object.freeze(["atMs", "funded"]);

// The two sides that hold keys. Distinct from ROLE_NAMES, which includes the
// verifier: the verifier signs a verdict but never registers an identity.
export const PARTY_ROLE_NAMES = Object.freeze(["payer", "payee"]);
export const IDENTITY_KEYS = Object.freeze(["address", "agentId"]);

export const SUBJECT_RUNS = Object.freeze(["rehearsal", "stakeholder"]);

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DECIMAL_INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const HTTP_URL_PATTERN = /^https?:\/\/\S+$/;

export class SnapshotValidationError extends Error {
  constructor(reason) {
    super(`Handshake snapshot is invalid: ${reason}`);
    this.name = new.target.name;
    this.category = "monitor-snapshot";
    this.code = "HANDSHAKE_SNAPSHOT_INVALID";
  }
}

function invalid(reason) {
  throw new SnapshotValidationError(reason);
}

function hasExactKeys(value, expectedKeys) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value)
  ) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isNonNegativeInteger(value) {
  return Number.isInteger(value) && value >= 0;
}

function isDecimalIntegerString(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 78 &&
    DECIMAL_INTEGER_PATTERN.test(value)
  );
}

function isUuid(value) {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

function isHttpUrl(value) {
  return typeof value === "string" && HTTP_URL_PATTERN.test(value);
}

function isStageValue(value) {
  return value === FAILED_STAGE || STATUSES.includes(value);
}

export function validateAnchor(kind, anchor) {
  if (anchor === null) return;
  if (!hasExactKeys(anchor, ANCHOR_KEYS)) {
    invalid(`anchors.${kind} has the wrong shape`);
  }
  if (anchor.kind !== kind) {
    invalid(`anchors.${kind}.kind does not match its own slot`);
  }
  if (!isDecimalIntegerString(anchor.blockHeight)) {
    invalid(`anchors.${kind}.blockHeight must be a decimal integer string`);
  }
  if (!isUuid(anchor.ledgerId)) {
    invalid(`anchors.${kind}.ledgerId must be a UUID`);
  }
  if (!isNonNegativeInteger(anchor.blockTime)) {
    invalid(`anchors.${kind}.blockTime must be an epoch-millisecond integer`);
  }
  if (
    typeof anchor.receipt !== "object" ||
    anchor.receipt === null ||
    Array.isArray(anchor.receipt)
  ) {
    invalid(`anchors.${kind}.receipt must be a receipt payload object`);
  }
  if (!isHttpUrl(anchor.explorerUrl)) {
    invalid(`anchors.${kind}.explorerUrl must be an http(s) URL`);
  }
  validateTerms(kind, anchor.terms);
  validateSignedBy(kind, anchor.signedBy);
}

function validateTerms(kind, terms) {
  if (terms === null) return;
  if (!hasExactKeys(terms, TERMS_KEYS)) {
    invalid(`anchors.${kind}.terms has the wrong shape`);
  }
  if (!isNonEmptyString(terms.currency)) {
    invalid(`anchors.${kind}.terms.currency must be a non-empty string`);
  }
  for (const field of ["value", "expirySeconds", "sequence"]) {
    if (!isDecimalIntegerString(String(terms[field]))) {
      invalid(`anchors.${kind}.terms.${field} must be a decimal integer string`);
    }
  }
  if (!isNonEmptyString(terms.sessionDigest)) {
    invalid(`anchors.${kind}.terms.sessionDigest must be a non-empty string`);
  }
  // The first transition has no predecessor; the other two name the block of
  // the receipt they follow, which is what makes the order a property of the
  // chain rather than of our logs.
  if (terms.predecessor !== null && !isDecimalIntegerString(String(terms.predecessor))) {
    invalid(`anchors.${kind}.terms.predecessor must be null or a block height`);
  }
}

function validateSignedBy(kind, signedBy) {
  if (signedBy === null) return;
  if (!hasExactKeys(signedBy, SIGNED_BY_KEYS)) {
    invalid(`anchors.${kind}.signedBy has the wrong shape`);
  }
  if (!/^0x[0-9a-f]{40}$/.test(String(signedBy.address))) {
    invalid(`anchors.${kind}.signedBy.address must be a lowercase 0x address`);
  }
  if (!isDecimalIntegerString(String(signedBy.agentId))) {
    invalid(`anchors.${kind}.signedBy.agentId must be a decimal integer string`);
  }
}

function validateStageHistory(stageHistory) {
  if (!Array.isArray(stageHistory) || stageHistory.length === 0) {
    invalid("stageHistory must be a non-empty array");
  }
  let previousAtMs = -1;
  for (const entry of stageHistory) {
    if (!hasExactKeys(entry, STAGE_HISTORY_ENTRY_KEYS)) {
      invalid("stageHistory entry has the wrong shape");
    }
    if (!isStageValue(entry.status)) {
      invalid(`stageHistory entry has an unknown status: ${entry.status}`);
    }
    if (!isNonNegativeInteger(entry.atMs)) {
      invalid("stageHistory entry.atMs must be a non-negative integer");
    }
    if (entry.atMs < previousAtMs) {
      invalid("stageHistory is not ordered by time");
    }
    previousAtMs = entry.atMs;
  }
  // The final history entry must agree with currentStage — checked by the
  // caller, which has both values in scope.
}

function validateHeartbeat(heartbeat) {
  if (!hasExactKeys(heartbeat, ROLE_NAMES)) {
    invalid("heartbeat must have exactly the three role keys");
  }
  for (const role of ROLE_NAMES) {
    const entry = heartbeat[role];
    if (entry === null) continue;
    if (!hasExactKeys(entry, HEARTBEAT_ENTRY_KEYS)) {
      invalid(`heartbeat.${role} has the wrong shape`);
    }
    if (!isNonNegativeInteger(entry.lastSeenMs)) {
      invalid(`heartbeat.${role}.lastSeenMs must be a non-negative integer`);
    }
  }
}

function validateFunding(funding) {
  if (funding === null) return;
  if (!hasExactKeys(funding, FUNDING_KEYS)) {
    invalid("funding has the wrong shape");
  }
  if (typeof funding.funded !== "boolean") {
    invalid("funding.funded must be a boolean");
  }
  if (funding.atMs !== null && !isNonNegativeInteger(funding.atMs)) {
    invalid("funding.atMs must be null or a non-negative integer");
  }
}

// The two ERC-8004 registrations, once each side has one. The agent id is what
// the registry itself returned, so an audience can look either party up on a
// public explorer while the run is still going. Narration only, like the rest
// of this shape: nothing here is consulted when deciding an outcome.
function validateIdentities(identities) {
  if (identities === null) return;
  if (!hasExactKeys(identities, PARTY_ROLE_NAMES)) {
    invalid("identities must have exactly the two party-role keys");
  }
  for (const role of PARTY_ROLE_NAMES) {
    const party = identities[role];
    if (party === null) continue;
    if (!hasExactKeys(party, IDENTITY_KEYS)) {
      invalid(`identities.${role} has the wrong shape`);
    }
    if (!/^[0-9]{1,20}$/.test(String(party.agentId))) {
      invalid(`identities.${role}.agentId must be a decimal integer string`);
    }
    if (!/^0x[0-9a-f]{40}$/.test(String(party.address))) {
      invalid(`identities.${role}.address must be a lowercase 0x address`);
    }
  }
}

function validateVerdict(verdict) {
  if (verdict === null) return;
  if (typeof verdict !== "object" || Array.isArray(verdict)) {
    invalid("verdict must be null or an object");
  }
  if (!isNonEmptyString(verdict.outcome)) {
    invalid("verdict.outcome must be a non-empty string");
  }
  if (verdict.paymentMoved !== false) {
    invalid("verdict.paymentMoved must be false");
  }
}

/**
 * Structurally validate a handshake snapshot. Throws SnapshotValidationError
 * on any violation; returns true otherwise. Does not know anything about
 * presentation — a view module (e.g. the stakeholder page) is responsible for
 * turning a valid snapshot into narration.
 */
export function validateSnapshot(snapshot) {
  if (!hasExactKeys(snapshot, SNAPSHOT_KEYS)) {
    invalid("top-level shape does not match SNAPSHOT_KEYS");
  }
  if (snapshot.schema !== SNAPSHOT_SCHEMA) {
    invalid("schema mismatch");
  }
  if (!isNonEmptyString(snapshot.sessionId)) {
    invalid("sessionId must be a non-empty string");
  }
  if (!SUBJECT_RUNS.includes(snapshot.subjectRun)) {
    invalid("subjectRun must be one of SUBJECT_RUNS");
  }
  if (!isStageValue(snapshot.currentStage)) {
    invalid("currentStage must be a known status or FAILED");
  }
  if (snapshot.currentStage === FAILED_STAGE) {
    if (!REASON_CODES.includes(snapshot.reasonCode)) {
      invalid("reasonCode must be a frozen reason code when currentStage is FAILED");
    }
  } else if (snapshot.reasonCode !== null) {
    invalid("reasonCode must be null unless currentStage is FAILED");
  }

  validateStageHistory(snapshot.stageHistory);
  const lastEntry = snapshot.stageHistory[snapshot.stageHistory.length - 1];
  if (lastEntry.status !== snapshot.currentStage) {
    invalid("the last stageHistory entry must match currentStage");
  }

  if (
    !hasExactKeys(snapshot.anchors, ANCHOR_KINDS)
  ) {
    invalid("anchors must have exactly the three anchor-kind keys");
  }
  for (const kind of ANCHOR_KINDS) {
    validateAnchor(kind, snapshot.anchors[kind]);
  }

  validateFunding(snapshot.funding);
  validateIdentities(snapshot.identities);
  validateHeartbeat(snapshot.heartbeat);

  if (snapshot.paymentMoved !== false) {
    invalid("paymentMoved must always be false");
  }

  validateVerdict(snapshot.verdict);
  // The run can only ever be authorized on the stakeholder sub-run; a
  // rehearsal snapshot publishing a non-null verdict is a structural bug in
  // whatever produced it, not a valid state to render.
  if (snapshot.verdict !== null && snapshot.subjectRun !== "stakeholder") {
    invalid("verdict must be null outside the stakeholder subjectRun");
  }

  if (!isNonNegativeInteger(snapshot.updatedAtMs)) {
    invalid("updatedAtMs must be a non-negative integer");
  }

  return true;
}

/**
 * Build a validated snapshot object from parts, filling in the few fields
 * that have an unambiguous default (paymentMoved, reasonCode when not
 * failed). Throws SnapshotValidationError if the result is not valid.
 */
export function buildSnapshot(input) {
  const snapshot = Object.freeze({
    anchors: Object.freeze({ ...input.anchors }),
    currentStage: input.currentStage,
    funding: input.funding ?? null,
    heartbeat: Object.freeze({ ...input.heartbeat }),
    identities: input.identities ?? null,
    paymentMoved: false,
    reasonCode:
      input.currentStage === FAILED_STAGE ? input.reasonCode ?? null : null,
    schema: SNAPSHOT_SCHEMA,
    sessionId: input.sessionId,
    stageHistory: Object.freeze(input.stageHistory.map((e) => Object.freeze({ ...e }))),
    subjectRun: input.subjectRun,
    updatedAtMs: input.updatedAtMs,
    verdict: input.verdict ?? null,
  });
  validateSnapshot(snapshot);
  return snapshot;
}

// --- Plain-English message maps -------------------------------------------
//
// One sentence per status and per reason code. Business language only: no
// stack traces, no internal identifiers, no code names. These are the
// generic, reusable sentences; a view (like the stakeholder page) may further
// group several statuses under one narrated step, but it must draw its base
// text from here rather than inventing new wording per status.

export const STATUS_MESSAGES = Object.freeze({
  SESSION_STARTED: "The run has started.",
  REHEARSAL_PASSED:
    "A private rehearsal confirmed the setup is ready. No terms have been made public yet.",
  TERMS_PUBLISHED: "The payer published the payment terms.",
  REQUEST_SUBMITTED: "The requestor submitted a payment request.",
  HANDSHAKE_REQUIRED:
    "Both sides are confirming who is who before anything is agreed.",
  IDENTITY_REGISTERED:
    "Each side's identity has been registered so it can be checked independently later.",
  FUNDED:
    "The accounts used for this demo have been funded. No customer money is at stake.",
  PROPOSED: "The requestor's payment request is now on the record.",
  ACCEPTED: "The requestor accepted the exact terms.",
  ACKNOWLEDGED: "The payer acknowledged the accepted terms.",
  EVIDENCE_RECEIVED: "The evidence from both sides has been collected.",
  VERIFYING: "An independent checker is verifying the evidence.",
  [FAILED_STAGE]: "The run stopped before authorization was reached.",
});

export const REASON_MESSAGES = Object.freeze({
  RENDEZVOUS_UNAVAILABLE:
    "The two sides could not reach each other to exchange messages.",
  EXPIRED: "A step took too long and the offer expired before it completed.",
  MISSING: "A required piece of evidence never arrived.",
  DUPLICATE: "The same step was submitted more than once.",
  REORDERED: "The steps arrived out of the required order.",
  MALFORMED: "A message did not match the required format.",
  AMBIGUOUS_WRITE:
    "It could not be confirmed whether a step was recorded, so it was treated as failed to be safe.",
  BINDING_MISMATCH:
    "The identities or terms in one step did not match an earlier step.",
  ANCHOR_UNVERIFIED:
    "A recorded step could not be independently confirmed on Clockchain.",
  ROLE_ALREADY_BOUND: "One side tried to take a role that was already claimed.",
  RATE_BLOCKED:
    "The request was temporarily blocked to prevent overload; it did not go through.",
  AMOUNT_UNRESOLVED:
    "The payment amount could not be pinned down to a single value.",
  FUNDING_REPLAYED:
    "A funding step was reused instead of happening fresh, so it was refused.",
  FAILED: "Something in the process failed and the run could not be authorized.",
  REHEARSAL_NOT_AUTHORIZABLE:
    "This was a private rehearsal, which is never allowed to reach a real authorization.",
  REHEARSAL_SUBJECT_MISMATCH:
    "The rehearsal did not match the run it was supposed to test, so it was rejected.",
});

/** True once every status and every reason code has a message. Used by tests. */
export function messageMapsAreComplete() {
  const statusesCovered = STATUSES.every((s) =>
    isNonEmptyString(STATUS_MESSAGES[s]),
  );
  const failedCovered = isNonEmptyString(STATUS_MESSAGES[FAILED_STAGE]);
  const reasonsCovered = REASON_CODES.every((r) =>
    isNonEmptyString(REASON_MESSAGES[r]),
  );
  return statusesCovered && failedCovered && reasonsCovered;
}

/** Plain sentence for whatever the snapshot's current stage is. */
export function stageSentence(snapshot) {
  return STATUS_MESSAGES[snapshot.currentStage] ?? "";
}

/** Plain sentence for the snapshot's reason code, or "" if there is none. */
export function reasonSentence(snapshot) {
  if (snapshot.reasonCode === null) return "";
  return REASON_MESSAGES[snapshot.reasonCode] ?? "";
}

/** Milliseconds since a given heartbeat entry last reported in. Null if the
 * role has never reported. */
export function msSinceHeartbeat(heartbeatEntry, nowMs) {
  if (heartbeatEntry === null) return null;
  return Math.max(0, nowMs - heartbeatEntry.lastSeenMs);
}

/** Milliseconds since the snapshot itself was last regenerated. */
export function msSinceUpdate(snapshot, nowMs) {
  return Math.max(0, nowMs - snapshot.updatedAtMs);
}
