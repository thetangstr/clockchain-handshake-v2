#!/usr/bin/env node
import { runDirectAgentSignerCli } from "../src/direct-agent-signer/main.mjs";

const SAFE_ERROR = Object.freeze({
  error: {
    code: "DIRECT_AGENT_SIGNER_FAILED",
    message: "Direct agent signer failed safely.",
  },
});

runDirectAgentSignerCli(process.argv.slice(2)).then(
  (value) => process.stdout.write(JSON.stringify(value) + "\n"),
  () => {
    process.stderr.write(JSON.stringify(SAFE_ERROR) + "\n");
    process.exitCode = 1;
  },
);
