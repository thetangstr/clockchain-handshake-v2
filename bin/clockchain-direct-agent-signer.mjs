#!/usr/bin/env node
import { runDirectAgentSignerCli } from "../src/direct-agent-signer/main.mjs";

function safeError(error) {
  const diagnosticCode = typeof error?.diagnosticCode === "string" &&
      /^DIRECT_SIGNER_[A-Z_]+$/.test(error.diagnosticCode)
    ? error.diagnosticCode
    : "DIRECT_SIGNER_INTERNAL_FAILURE";
  return {
    error: {
      code: "DIRECT_AGENT_SIGNER_FAILED",
      diagnosticCode,
      message: "Direct agent signer failed safely.",
    },
  };
}

runDirectAgentSignerCli(process.argv.slice(2)).then(
  (value) => process.stdout.write(JSON.stringify(value) + "\n"),
  (error) => {
    process.stderr.write(JSON.stringify(safeError(error)) + "\n");
    process.exitCode = 1;
  },
);
