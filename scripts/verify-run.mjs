#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { validateFreshAgentAttemptArtifact } from "../src/testing/fresh-agent-client.mjs";

const SAFE_FAILURE = "Fresh agent run verification failed safely.\n";
const MAX_ARTIFACT_BYTES = 1024 * 1024;
const SUMMARY_SCHEMA = "clockchain.fresh-agent-canary-verification/v1";

function fail() {
  throw new Error("invalid");
}

async function readJson(path) {
  if (typeof path !== "string" || path.length === 0) fail();
  const text = await readFile(path, "utf8");
  if (Buffer.byteLength(text, "utf8") > MAX_ARTIFACT_BYTES) fail();
  return JSON.parse(text);
}

function roleSummary(role) {
  return Object.freeze({
    address: role.address,
    erc8004AgentId: role.erc8004.agentId,
    erc8004Reference: role.erc8004.reference,
  });
}

function summarize(artifact) {
  const evidence = artifact.result;
  const initiator = evidence.roles.initiator;
  const responder = evidence.roles.responder;
  return Object.freeze({
    schema: SUMMARY_SCHEMA,
    attemptId: artifact.attemptId,
    certificateVerified: true,
    externalBusinessActionPerformed: false,
    cleanup: evidence.cleanup.completed,
    distinctAddresses: initiator.address !== responder.address,
    distinctErc8004Ids: initiator.erc8004.agentId !== responder.erc8004.agentId,
    certificateDigest: evidence.binding.certificateDigest,
    receiptIds: initiator.receiptIds,
    roles: Object.freeze({
      initiator: roleSummary(initiator),
      responder: roleSummary(responder),
    }),
  });
}

export async function verifyFreshAgentAttemptFiles(paths) {
  if (!Array.isArray(paths) || paths.length < 1) fail();
  const artifacts = [];
  for (const path of paths) {
    artifacts.push(validateFreshAgentAttemptArtifact(await readJson(path)));
  }
  return Object.freeze(artifacts.map(summarize));
}

async function main(argv = process.argv.slice(2), {
  stderr = process.stderr,
  stdout = process.stdout,
} = {}) {
  try {
    const summaries = await verifyFreshAgentAttemptFiles(argv);
    for (const summary of summaries) stdout.write(`${JSON.stringify(summary)}\n`);
  } catch {
    stderr.write(SAFE_FAILURE);
    process.exitCode = 1;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
