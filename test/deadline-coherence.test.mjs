// The deadline invariants. A previous build failed eleven consecutive live runs,
// twice to timeout misalignment; the last fix shipped at 00:58 and run 12 was never
// attempted. These tests exist so that class of bug cannot return silently.
//
// Every case uses an explicit clock value. There are no real timers here — a
// timer-bound test would itself violate the fast-suite rule.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  ACK_WRITE_BUDGET_MS,
  MIN_USABLE_POLL_MS,
  computeAcceptedPollBound,
} from "../src/core/window.mjs";
import { EXPIRY_WINDOW_MS, deadlineMs } from "../src/core/blocktime.mjs";
import { DESCRIPTOR_EXPIRY_SECONDS } from "../src/core/descriptor.mjs";
import {
  MAX_POLL_DURATION_MS,
  MIN_POLL_INTERVAL_MS,
} from "../src/core/runner.mjs";

const BLOCK_TIME = 1_800_000_000_000;
const DEADLINE = deadlineMs(BLOCK_TIME);

test("the poll bound never consumes the acknowledgment reservation", () => {
  for (const elapsed of [0, 1_000, 60_000, 200_000, 350_000]) {
    const result = computeAcceptedPollBound({
      nowMs: BLOCK_TIME + elapsed,
      proposalDeadlineMs: DEADLINE,
    });
    if (!result.ok) continue;
    const watchEnds = BLOCK_TIME + elapsed + result.pollDurationMs;
    assert.ok(
      DEADLINE - watchEnds >= ACK_WRITE_BUDGET_MS,
      `at +${elapsed}ms the watch leaves only ${DEADLINE - watchEnds}ms for the ACKNOWLEDGED write`,
    );
  }
});

test("a full remaining window does NOT yield a full-window bound", () => {
  // The regression this file exists for. An earlier revision asserted only
  // "bound <= EXPIRY_WINDOW_MS", which 600000 <= 600000 satisfies — so a bound
  // consuming the entire window passed the check and left zero time to
  // acknowledge. The bound must be strictly smaller, by the reservation.
  const result = computeAcceptedPollBound({
    nowMs: BLOCK_TIME,
    proposalDeadlineMs: DEADLINE,
  });
  assert.equal(result.ok, true);
  assert.ok(
    result.pollDurationMs < EXPIRY_WINDOW_MS,
    "a bound equal to the whole window must never be produced",
  );
  assert.equal(result.pollDurationMs, EXPIRY_WINDOW_MS - ACK_WRITE_BUDGET_MS);
});

test("a late ACCEPTED discovery still leaves the full write budget", () => {
  // Worst case inside a successful watch: ACCEPTED appears on the final poll.
  const result = computeAcceptedPollBound({
    nowMs: BLOCK_TIME,
    proposalDeadlineMs: DEADLINE,
  });
  assert.equal(result.ok, true);
  const discoveredAt = BLOCK_TIME + result.pollDurationMs;
  assert.ok(DEADLINE - discoveredAt >= ACK_WRITE_BUDGET_MS);
});

test("a depleted window closes with a named EXPIRED, never a generic failure", () => {
  // pollDuration() in the ported runner throws a generic terminal FAILED below its
  // floor. The caller must decide first, so the public reason stays named.
  const result = computeAcceptedPollBound({
    nowMs: DEADLINE - ACK_WRITE_BUDGET_MS - (MIN_USABLE_POLL_MS - 1),
    proposalDeadlineMs: DEADLINE,
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "EXPIRED");
  assert.notEqual(result.reason, "FAILED");
  assert.match(result.detail, /window/i);
});

test("a window already past its deadline closes EXPIRED", () => {
  const result = computeAcceptedPollBound({
    nowMs: DEADLINE + 1,
    proposalDeadlineMs: DEADLINE,
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "EXPIRED");
});

test("any produced bound is acceptable to the ported runner", () => {
  // The runner accepts [MIN_POLL_INTERVAL_MS, MAX_POLL_DURATION_MS]. If we ever
  // hand it something outside that range it throws the generic code.
  for (const elapsed of [0, 100_000, 300_000, 376_400]) {
    const result = computeAcceptedPollBound({
      nowMs: BLOCK_TIME + elapsed,
      proposalDeadlineMs: DEADLINE,
    });
    if (!result.ok) continue;
    assert.ok(result.pollDurationMs >= MIN_POLL_INTERVAL_MS);
    assert.ok(result.pollDurationMs <= MAX_POLL_DURATION_MS);
  }
});

test("the reservation covers a full worst-case Clockchain write", () => {
  // 223.5s is the observed rate-limit-bounded ceiling for one write. If this ever
  // drops below it, a throttled ACKNOWLEDGED write can miss the deadline.
  assert.ok(ACK_WRITE_BUDGET_MS >= 223_500);
});

test("the signed expiry constant is unchanged at 600 seconds", async () => {
  // expirySeconds is a canonical descriptor field inside dSession. Changing it
  // changes every Clockchain reference id and invalidates the ported vectors, so
  // v2 fixes the deadline problem by sequencing instead. This asserts nobody
  // "fixed" it the tempting way.
  assert.equal(DESCRIPTOR_EXPIRY_SECONDS, "600");
  assert.equal(EXPIRY_WINDOW_MS, 600_000);
  const source = await readFile(
    new URL("../src/core/descriptor.mjs", import.meta.url),
    "utf8",
  );
  assert.match(source, /DESCRIPTOR_EXPIRY_SECONDS = "600"/);
});

test("no human-paced wait is configured inside the window", () => {
  // The whole window is smaller than the minimum human-paced wait (30 min). If a
  // human-paced bound were ever placed in-window, this relationship would break.
  const HUMAN_PACED_MINIMUM_MS = 30 * 60_000;
  assert.ok(
    EXPIRY_WINDOW_MS < HUMAN_PACED_MINIMUM_MS,
    "the anchor window must stay strictly machine-paced",
  );
  assert.equal(MAX_POLL_DURATION_MS, HUMAN_PACED_MINIMUM_MS);
});
