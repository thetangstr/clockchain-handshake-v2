#!/usr/bin/env node

import { waitForFreshInvitationWindow } from "../src/testing/live-invitation-window.mjs";

process.stdout.write("Waiting for a fresh Clockchain invitation window…\n");
try {
  const ready = await waitForFreshInvitationWindow();
  process.stdout.write(`Fresh invitation window ready for session ${ready.sessionId}.\n`);
} catch {
  process.stderr.write("A fresh Clockchain invitation window did not become available. No agents were started.\n");
  process.exitCode = 1;
}
