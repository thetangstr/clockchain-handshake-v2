/**
 * In-window timing arithmetic for the anchor phase.
 *
 * Why this module exists: a previous build failed eleven consecutive live runs,
 * twice to timeout misalignment. The last failure killed runs at exactly eight
 * minutes while the remote stakeholder was still running `npm ci`. The fix is not
 * a bigger constant — it is a clear split between two kinds of waiting:
 *
 *   Pre-window  (human-paced): everything up to and including both parties
 *               signalling readiness. Bounds here are >= 30 minutes, resumable,
 *               with heartbeats. No anchor exists yet, so nothing can expire.
 *
 *   In-window   (machine-paced): PROPOSED -> ACCEPTED -> ACKNOWLEDGED. Bounded by
 *               the signed 10-minute descriptor expiry, which is a canonical field
 *               inside dSession and therefore cannot be changed without
 *               invalidating every Clockchain reference id.
 *
 * The window opens at the PROPOSED BLOCK TIME, not when the write returns — the
 * ledger stamps it before the caller hears back. And after ACCEPTED is found, the
 * ACKNOWLEDGED write still needs its own budget. So the watch bound is dynamic:
 * whatever is left, minus a reservation for that final write. Handing the whole
 * window to the watch is exactly how a run reaches ACCEPTED and then dies.
 */

/** Clockchain's observed worst-case single-write ceiling (rate-limit bounded). */
export const ACK_WRITE_BUDGET_MS = 223_500;

/** Mirrors runner.mjs MIN_POLL_INTERVAL_MS; a bound below this is unusable. */
export const MIN_USABLE_POLL_MS = 20_000;

/**
 * Mirrors runner.mjs MAX_POLL_DURATION_MS. Duplicated rather than imported to
 * keep this module dependency-free; the deadline-coherence test asserts the two
 * stay equal, so a drift is caught rather than silently tolerated.
 */
export const RUNNER_MAX_POLL_DURATION_MS = 30 * 60_000;

/** The signed protocol window (blocktime.mjs EXPIRY_WINDOW_MS), asserted equal in test. */
export const EXPIRY_WINDOW_MS = 600_000;

/**
 * Compute the bound for the in-window ACCEPTED watch.
 *
 * Returns either {ok:true, pollDurationMs} or {ok:false, reason} — never a bound
 * that consumes the reservation. The caller MUST check `ok` before calling the
 * runner: pollDuration() throws a generic terminal FAILED below its floor, and a
 * generic code would violate the rule that every stop has a named public reason.
 */
export function computeAcceptedPollBound({
  ackWriteBudgetMs = ACK_WRITE_BUDGET_MS,
  nowMs,
  proposalDeadlineMs,
}) {
  if (
    !Number.isSafeInteger(nowMs) ||
    !Number.isSafeInteger(proposalDeadlineMs) ||
    !Number.isSafeInteger(ackWriteBudgetMs)
  ) {
    return Object.freeze({
      detail: "Timing inputs were not whole millisecond values.",
      ok: false,
      reason: "MALFORMED",
    });
  }

  // The reservation is a floor, not a suggestion. A caller passing 0 (or any
  // value below the observed single-write ceiling) would otherwise be handed the
  // entire window and reach the deadline with nothing left to acknowledge —
  // the exact failure this module exists to prevent, reintroduced through an
  // argument. Callers may reserve MORE, never less.
  const reservedMs = Math.max(ackWriteBudgetMs, ACK_WRITE_BUDGET_MS);

  // The window can never legitimately exceed the signed expiry. A larger value
  // means a bad PROPOSED block time or clock skew; trusting it would produce a
  // bound the runner rejects with a generic terminal code.
  const remainingMs = Math.min(
    proposalDeadlineMs - nowMs,
    EXPIRY_WINDOW_MS,
  );
  const usableMs = Math.min(
    remainingMs - reservedMs,
    RUNNER_MAX_POLL_DURATION_MS,
  );

  if (usableMs < MIN_USABLE_POLL_MS) {
    return Object.freeze({
      // Deliberately non-secret and plain: this string reaches a business audience.
      detail:
        "The authorization window is too depleted to finish the handshake safely.",
      ok: false,
      reason: "EXPIRED",
    });
  }

  return Object.freeze({ ok: true, pollDurationMs: usableMs });
}

/** Minimum lifetime for any artifact a human is expected to act within. */
export const HUMAN_PACED_MINIMUM_MS = 30 * 60_000;

/**
 * Guard the construction of a payer mandate.
 *
 * The mandate is published BEFORE a human-paced wait: the payer publishes terms,
 * then waits for a stakeholder to paste a prompt, install a kit, and submit a
 * request. A mandate with a short lifetime therefore expires while the payer is
 * still legitimately waiting — and because expiresAtMs is a constructed value
 * rather than a named constant, no identifier sweep can catch it.
 *
 * This lives here rather than in payer-mandate.mjs because that module is a pure
 * port: it is byte-faithful with the donor and its own validator deliberately
 * accepts the donor's shorter-lived fixtures. v2 enforces the stronger rule at the
 * point of construction, which is the only place that can know about the
 * discovery document it must outlive.
 */
export function assertMandateLifetime({
  discoveryExpiresAtMs,
  expiresAtMs,
  issuedAtMs,
}) {
  const issued = Number(issuedAtMs);
  const expires = Number(expiresAtMs);
  if (!Number.isSafeInteger(issued) || !Number.isSafeInteger(expires)) {
    return Object.freeze({
      detail: "Mandate timestamps were not whole millisecond values.",
      ok: false,
      reason: "MALFORMED",
    });
  }
  if (expires - issued < HUMAN_PACED_MINIMUM_MS) {
    return Object.freeze({
      detail:
        "The payment terms would expire before a person could reasonably respond.",
      ok: false,
      reason: "EXPIRED",
    });
  }
  if (
    discoveryExpiresAtMs !== undefined &&
    expires < Number(discoveryExpiresAtMs)
  ) {
    return Object.freeze({
      detail:
        "The payment terms would expire before the published session does.",
      ok: false,
      reason: "EXPIRED",
    });
  }
  return Object.freeze({ ok: true });
}
