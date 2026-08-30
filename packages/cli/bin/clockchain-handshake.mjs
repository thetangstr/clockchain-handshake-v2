#!/usr/bin/env node
import process from "node:process";

import { formatHandshakeCliFailure, runHandshakeCliCommand } from "../src/index.mjs";

async function readJsonInput() {
  let text = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) text += chunk;
  text = text.trim();
  return text.length === 0 ? {} : JSON.parse(text);
}

const [command, toolName] = process.argv.slice(2);
const commandsWithInput = new Set([
  "validate-tool-input",
  "validate-tool-result",
  "prepare-signing",
  "verify-result",
  "verify-certificate",
]);
let output;
try {
  const input = commandsWithInput.has(command) ? await readJsonInput() : {};
  output = await runHandshakeCliCommand(command, input, { toolName });
} catch (error) {
  output = formatHandshakeCliFailure(command || "unknown", {
    ...error,
    code: "SCHEMA_INVALID",
  });
}

process.stdout.write(`${JSON.stringify(output)}\n`);
process.exitCode = output.ok ? 0 : 1;
