#!/usr/bin/env node
import process from "node:process";

import { formatHandshakeCliFailure, runHandshakeCliCommand } from "../src/index.mjs";
import { readHandshakeCliJsonInput } from "../src/stdin.mjs";

const [command, toolName] = process.argv.slice(2);
const commandsWithInput = new Set([
  "validate-tool-input",
  "validate-tool-result",
  "prepare-signing",
  "verify-result-fixture",
  "verify-certificate-fixture",
]);
let output;
try {
  const input = commandsWithInput.has(command) ? await readHandshakeCliJsonInput(process.stdin) : {};
  output = await runHandshakeCliCommand(command, input, { toolName });
} catch (error) {
  output = formatHandshakeCliFailure(command || "unknown", {
    ...error,
    code: "SCHEMA_INVALID",
  });
}

process.stdout.write(`${JSON.stringify(output)}\n`);
process.exitCode = output.ok ? 0 : 1;
