#!/usr/bin/env node
/**
 * Preflight, in plain English.
 *
 * Four things have to be true before a demo starts. Each one is checked for
 * real -- the ledger check spends an actual round trip rather than looking for
 * a file, because a token that exists and a token that works are different
 * facts, and the second is the one that matters with an audience in the room.
 *
 * Prints a sentence per check and exits non-zero if any fails.
 */
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { createPublicClient, formatEther, http } from "viem";
import { sepolia } from "viem/chains";

import { createMcpClient } from "../src/core/clockchain.mjs";
import { openFundingWallet } from "../src/core/funding/wallet.mjs";
import { RPC_URL } from "../src/core/constants.mjs";

const RELAY = process.env.HANDSHAKE_RELAY ?? "http://44.249.47.220:8080";
const ROOT = process.cwd();

const results = [];

async function check(what, fn) {
  try {
    const detail = await fn();
    results.push({ ok: true, what, detail });
  } catch (error) {
    results.push({ ok: false, what, detail: error?.message ?? String(error) });
  }
}

await check("Node is new enough to run this", async () => {
  const major = Number(process.versions.node.split(".")[0]);
  if (major < 22) throw new Error(`Node ${process.versions.node}; this needs 22 or higher`);
  return `Node ${process.versions.node}`;
});

await check("The payment service both sides talk through is awake", async () => {
  const res = await fetch(`${RELAY}/healthz`, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`relay answered ${res.status}`);
  const body = await res.json();
  if (body.paymentMoved !== false) throw new Error("relay is not reporting paymentMoved:false");
  return `${RELAY} answered, ${body.sessions} session(s) held`;
});

await check("The treasury can cover the network fee", async () => {
  const wallet = await openFundingWallet({ keystorePath: join(ROOT, "keys/funding-wallet.json") });
  const address = wallet.metadata.fundingAddress;
  const client = createPublicClient({ chain: sepolia, transport: http(RPC_URL) });
  const balance = await client.getBalance({ address });
  const eth = Number(formatEther(balance));
  // Each run funds two registrations at 0.01 ETH plus gas; below this there is
  // not enough left to be worth starting in front of people.
  if (eth < 0.05) throw new Error(`only ${eth} testnet ETH left at ${address}`);
  return `${address} holds ${eth.toFixed(3)} testnet ETH`;
});

await check("We can reach the ledger and our token is accepted", async () => {
  const token = (await readFile(join(ROOT, "keys/clockchain.token"), "utf8")).trim();
  if (token === "") throw new Error("keys/clockchain.token is empty");
  const stamp = await createMcpClient({ token }).getTimestamp();
  if (stamp?.nodeStatus !== "Synced") {
    throw new Error(`ledger answered but reports nodeStatus=${stamp?.nodeStatus ?? "unknown"}`);
  }
  return `ledger is Synced at block ${stamp.blockHeight}`;
});

const width = Math.max(...results.map((r) => r.what.length));
for (const { ok, what, detail } of results) {
  process.stdout.write(`${ok ? "OK  " : "FAIL"}  ${what.padEnd(width)}   ${detail}\n`);
}

const failed = results.filter((r) => !r.ok);
if (failed.length === 0) {
  process.stdout.write("\nAll four checks passed. Safe to start the demo.\n");
  process.exit(0);
}
process.stdout.write(
  `\n${failed.length} check(s) failed. Fix these before the audience is in the room —\n` +
  `the runbook's troubleshooting section covers each one.\n`,
);
process.exit(1);
