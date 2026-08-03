#!/usr/bin/env node
/**
 * The Requestor kit — the only thing a stakeholder runs.
 *
 * It receives a relay URL and a session id and nothing else: no key, no token, no
 * invitation. It generates its own keypair, asks to be paid, follows whatever the
 * payer's response tells it to do, registers its own on-chain identity, and
 * records its acceptance. It never claims the run succeeded — only the operator's
 * independent verifier can say that, and this says so out loud.
 */
import { chmod, mkdir, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createPublicClient, createWalletClient, http } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";

import * as relay from "../src/relay/client.mjs";
import { say, stop } from "../src/roles/session.mjs";
import { createMcpClient, mintDemoToken } from "../src/core/clockchain.mjs";
import { ERC8004_ABI } from "../src/core/registration.mjs";
import { runPayeeRole } from "../src/core/roles-core.mjs";
import { REGISTRY_ADDRESS, RPC_URL } from "../src/core/constants.mjs";

const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i], process.argv[i + 1]);
const RELAY_URL = args.get("--relay-url") ?? process.env.HANDSHAKE_RELAY;
const SESSION_ID = args.get("--session") ?? process.env.HANDSHAKE_SESSION;
if (!RELAY_URL || !SESSION_ID) {
  stop("MALFORMED", "This needs a relay URL and a session id, and nothing else.");
}

// Human-paced throughout: the operator has to fund us on a public testnet, which
// takes as long as it takes. Nothing here has an anchor yet, so nothing can expire.
const WAIT_MS = 45 * 60_000;
const HEARTBEAT_MS = 20_000;

const publicClient = createPublicClient({ chain: sepolia, transport: http(RPC_URL) });

async function awaitKind(kind, budgetMs, after = "0") {
  const deadline = Date.now() + budgetMs;
  let cursor = after;
  let lastBeat = 0;
  while (Date.now() < deadline) {
    const got = await relay.pollMessages({
      relayUrl: RELAY_URL, sessionId: SESSION_ID, after: cursor, waitMs: 20_000,
    });
    for (const message of got.messages ?? []) {
      cursor = message.seq;
      if (message.kind === kind) return message;
    }
    if (Date.now() - lastBeat > HEARTBEAT_MS) {
      lastBeat = Date.now();
      say("REQUEST_SUBMITTED", "Still working — waiting on the payer. No money has moved.");
    }
  }
  stop("EXPIRED", "The payer did not respond before the session window closed.");
}

async function main() {
  say("SESSION_STARTED", "Asking to be paid. This is a verification exercise: no money will move.");

  // Our own key, generated here. The operator never sees it and cannot produce it.
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  const kp = relay.generateEnvelopeKeyPair();
  say("REQUEST_SUBMITTED", "Generated a fresh identity key for this run.", { address: account.address });

  await relay.postMessage({
    relayUrl: RELAY_URL, sessionId: SESSION_ID,
    envelope: relay.signEnvelope({
      sessionId: SESSION_ID, seq: "1", role: "requestor", kind: "identity_ready",
      body: { address: account.address, paymentMoved: false },
      senderKey: kp.senderKey, privateKeyPem: kp.privateKeyPem,
    }),
  });
  say("HANDSHAKE_REQUIRED",
    "The payer will not consider a payment without a verified handshake first. Following its instructions.");

  await awaitKind("funding_record", WAIT_MS);
  say("FUNDED", "The operator covered our registration gas. Registering an on-chain identity.");

  const wallet = createWalletClient({ account, chain: sepolia, transport: http(RPC_URL) });
  const tx = await wallet.writeContract({
    abi: ERC8004_ABI,
    address: REGISTRY_ADDRESS,
    args: [`https://clockchain-research.vercel.app/handshake/agent/${account.address}`],
    functionName: "register",
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash: tx, timeout: 180_000 });
  const ZERO = `0x${"0".repeat(64)}`;
  let agentId = null;
  for (const log of receipt.logs) {
    if (log.address.toLowerCase() !== REGISTRY_ADDRESS.toLowerCase()) continue;
    if (log.topics.length !== 4 || log.topics[1] !== ZERO) continue;
    agentId = BigInt(log.topics[3]).toString();
  }
  if (!agentId) stop("FAILED", "Could not read our identity id back from the registry.");
  say("IDENTITY_REGISTERED", `Registered on-chain identity #${agentId}.`, { agentId });

  await relay.postMessage({
    relayUrl: RELAY_URL, sessionId: SESSION_ID,
    envelope: relay.signEnvelope({
      sessionId: SESSION_ID, seq: "2", role: "requestor", kind: "party_ready",
      body: { address: account.address, agentId, paymentMoved: false },
      senderKey: kp.senderKey, privateKeyPem: kp.privateKeyPem,
    }),
  });

  const handshake = await awaitKind("handshake_required", WAIT_MS);
  const { descriptorEnvelope, repositoryPublicKey } = handshake.body;
  say("PROPOSED", "Received the signed terms. Checking them and recording our acceptance.");

  const root = await mkdtemp(join(tmpdir(), "handshake-req-"));
  const directory = join(root, "payee");
  await mkdir(directory, { mode: 0o700, recursive: true });
  await chmod(directory, 0o700);

  const token = await mintDemoToken({});
  await runPayeeRole({
    client: createMcpClient({ token }),
    descriptorEnvelope,
    outputDirectory: directory,
    ownerOf: ({ agentId: id, registry }) =>
      publicClient.readContract({ abi: ERC8004_ABI, address: registry, args: [BigInt(id)], functionName: "ownerOf" }),
    repositoryPublicKey,
    signMessage: (bytes) => account.signMessage({ message: { raw: bytes } }),
  });

  say("ACCEPTED", "Our acceptance of the exact terms is recorded on Clockchain.");
  process.stdout.write(
    "\nOur side is complete — and that is NOT authorization.\n" +
    "Only the operator's independent verifier decides the outcome, after re-checking\n" +
    "every piece of evidence from scratch. No money has moved at any point.\n" +
    `\nEvidence: ${directory}\n`,
  );
}

main().catch((error) => {
  if (process.env.HANDSHAKE_DEBUG) process.stderr.write(`${error?.stack}\n`);
  stop(error?.terminalCode ?? error?.code ?? "FAILED", error?.message ?? "The run stopped.");
});
