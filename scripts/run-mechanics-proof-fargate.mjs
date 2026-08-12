#!/usr/bin/env node

import {
  buildFargateLivePreflightPlan,
  buildFargateDryRunSummary,
  loadFargateDryRunPlan,
} from "../src/runtime/aws-fargate-runtime-adapter.mjs";

function fail() {
  process.stderr.write("Fargate mechanics proof runner failed safely.\n");
  process.exitCode = 1;
}

async function main() {
  try {
    if (process.argv.length === 3 && process.argv[2] === "--dry-run") {
      const plan = await loadFargateDryRunPlan();
      const summary = buildFargateDryRunSummary(plan);
      process.stdout.write(`${JSON.stringify(summary)}\n`);
      return;
    }
    if (
      process.argv.length === 10 &&
      process.argv[2] === "--preflight" &&
      process.argv[3] === "--pair" &&
      process.argv[5] === "--direct-a2a" &&
      process.argv[6] === "--evidence-dir" &&
      process.argv[8] === "--app-image"
    ) {
      const plan = await loadFargateDryRunPlan();
      const summary = await buildFargateLivePreflightPlan({
        plan,
        pair: process.argv[4],
        directA2A: true,
        mcpUrl: "https://mcp.clockchain.network/handshake/mcp",
        evidenceDir: process.argv[7],
        appImage: process.argv[9],
      });
      process.stdout.write(`${JSON.stringify(summary)}\n`);
      return;
    }
    fail();
  } catch {
    fail();
  }
}

await main();
