#!/usr/bin/env node

import {
  buildFargateDryRunSummary,
  loadFargateDryRunPlan,
} from "../src/runtime/aws-fargate-runtime-adapter.mjs";

function fail() {
  process.stderr.write("Fargate mechanics proof runner failed safely.\n");
  process.exitCode = 1;
}

async function main() {
  if (process.argv.length !== 3 || process.argv[2] !== "--dry-run") {
    fail();
    return;
  }
  try {
    const plan = await loadFargateDryRunPlan();
    const summary = buildFargateDryRunSummary(plan);
    process.stdout.write(`${JSON.stringify(summary)}\n`);
  } catch {
    fail();
  }
}

await main();
