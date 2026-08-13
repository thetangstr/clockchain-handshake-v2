import assert from "node:assert/strict";
import test from "node:test";

import { waitForFreshInvitationWindow } from "../src/testing/live-invitation-window.mjs";

function snapshot({ createdAtMs = null, invitationExpiresAtMs, sessionId }) {
  return {
    schema: "clockchain.agent-handshake-snapshot/v2",
    sessionId,
    invitation: { createdAtMs, responderClaimedAtMs: null },
    timing: {
      invitationExpiresAtMs,
      sessionDeadlineMs: invitationExpiresAtMs + 8 * 60_000,
    },
    certificate: null,
    failure: null,
  };
}

test("waits through stale and already-used sessions until a fresh invitation window is available", async () => {
  let nowMs = 1_000_000;
  const responses = [
    snapshot({ invitationExpiresAtMs: nowMs + 20_000, sessionId: "11111111-1111-4111-8111-111111111111" }),
    snapshot({ createdAtMs: nowMs - 1_000, invitationExpiresAtMs: nowMs + 110_000, sessionId: "22222222-2222-4222-8222-222222222222" }),
    snapshot({ invitationExpiresAtMs: nowMs + 110_000, sessionId: "33333333-3333-4333-8333-333333333333" }),
  ];
  let sleeps = 0;
  const result = await waitForFreshInvitationWindow({
    fetchFn: async () => ({ ok: true, json: async () => responses.shift() }),
    minRemainingMs: 90_000,
    now: () => nowMs,
    pollMs: 2_000,
    sleep: async (delayMs) => {
      assert.equal(delayMs, 2_000);
      sleeps += 1;
      nowMs += delayMs;
    },
    timeoutMs: 30_000,
  });

  assert.deepEqual(result, {
    invitationExpiresAtMs: 1_110_000,
    sessionId: "33333333-3333-4333-8333-333333333333",
  });
  assert.equal(sleeps, 2);
});

test("fails closed when no fresh invitation window arrives before the deadline", async () => {
  let nowMs = 2_000_000;
  await assert.rejects(
    waitForFreshInvitationWindow({
      fetchFn: async () => ({ ok: false }),
      minRemainingMs: 90_000,
      now: () => nowMs,
      pollMs: 2_000,
      sleep: async (delayMs) => { nowMs += delayMs; },
      timeoutMs: 4_000,
    }),
    /fresh invitation window/i,
  );
});
