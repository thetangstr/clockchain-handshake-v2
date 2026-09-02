#!/usr/bin/env node
import {
  agentHandshakeCliSafeError,
  runAgentHandshakeCli,
} from "../src/agent-cli/main.mjs";

runAgentHandshakeCli(process.argv.slice(2)).then(
  (value) => process.stdout.write(JSON.stringify(value) + "\n"),
  (error) => {
    process.stderr.write(JSON.stringify(agentHandshakeCliSafeError(error)) + "\n");
    process.exitCode = 1;
  },
);
