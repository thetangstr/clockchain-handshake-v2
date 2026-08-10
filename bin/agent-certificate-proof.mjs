#!/usr/bin/env node

import { readFile } from "node:fs/promises";

import { verifyAgentHandshakeResult } from "../src/agent-handshake/result.mjs";

const args = process.argv.slice(2);

try {
  if (
    args.length !== 8 ||
    args[0] !== "--file" ||
    args[2] !== "--role" ||
    args[4] !== "--expected-public-key" ||
    args[6] !== "--session-id" ||
    !["initiator", "responder"].includes(args[3])
  ) throw new Error("invalid");
  const envelope = JSON.parse(await readFile(args[1], "utf8"));
  const proof = verifyAgentHandshakeResult(envelope, {
    expectedPublicKey: args[5],
    expectedRole: args[3],
    expectedSessionId: args[7],
  });
  process.stdout.write(`${JSON.stringify(proof)}\n`);
} catch {
  process.stderr.write("Generic handshake certificate verification failed.\n");
  process.exitCode = 1;
}
