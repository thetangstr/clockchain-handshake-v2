#!/usr/bin/env node
import { runAgentHandshakeCli } from "../src/agent-cli/main.mjs";

const SAFE_ERROR = Object.freeze({
  error: {
    code: "AGENT_HANDSHAKE_FAILED",
    message: "Agent handshake operation failed safely.",
  },
});

runAgentHandshakeCli(process.argv.slice(2)).then(
  (value) => process.stdout.write(JSON.stringify(value) + "\n"),
  () => {
    process.stderr.write(JSON.stringify(SAFE_ERROR) + "\n");
    process.exitCode = 1;
  },
);
