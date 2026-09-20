#!/usr/bin/env node
import { runAgentHandshakeCli } from "../src/agent-cli/main.mjs";
import { isSigningWindowExpired, SIGNING_WINDOW_EXPIRED_MESSAGE } from "../src/agent-cli/signing-request.mjs";

const SAFE_ERROR = Object.freeze({
  error: {
    code: "AGENT_HANDSHAKE_FAILED",
    message: "Agent handshake operation failed safely.",
  },
});
const WINDOW_EXPIRED_ERROR = Object.freeze({
  error: {
    code: "AGENT_HANDSHAKE_SIGNING_WINDOW_EXPIRED",
    message: SIGNING_WINDOW_EXPIRED_MESSAGE,
  },
});

runAgentHandshakeCli(process.argv.slice(2)).then(
  (value) => process.stdout.write(JSON.stringify(value) + "\n"),
  (error) => {
    process.stderr.write(JSON.stringify(isSigningWindowExpired(error) ? WINDOW_EXPIRED_ERROR : SAFE_ERROR) + "\n");
    process.exitCode = 1;
  },
);
