#!/usr/bin/env node
/**
 * Operator + Payer.
 *
 * Publishes a signed discovery document to the relay, waits (human-paced, with a
 * heartbeat) for a requestor to appear from wherever it is, funds and registers
 * whatever address that requestor generated for itself, publishes the signed
 * session descriptor, then drives the payer side of the handshake.
 *
 * The requestor never receives a key, a token, or a secret of any kind — only a
 * URL. Everything it needs to act arrives in responses it can verify.
 */
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createPublicClient, createWalletClient, http, parseEther } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";

import * as relay from "../src/relay/client.mjs";
import { buildSession, say, stop, DISCOVERY_SCHEMA } from "../src/roles/session.mjs";
import { createMcpClient } from "../src/core/clockchain.mjs";
import { createSignedEnvelope } from "../src/core/descriptor.mjs";
import { openFundingWallet } from "../src/core/funding/wallet.mjs";
import { ERC8004_ABI } from "../src/core/registration.mjs";
import { runPayerRole } from "../src/core/roles-core.mjs";
import { verifyBilateralAuthorization } from "../src/core/verdict.mjs";
import { REGISTRY_ADDRESS, RPC_URL } from "../src/core/constants.mjs";

const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i], process.argv[i + 1]);
const RELAY_URL = args.get("--relay-url") ?? process.env.HANDSHAKE_RELAY ?? "http://127.0.0.1:8080";
const KEYSTORE = args.get("--keystore") ?? join(process.cwd(), "keys/funding-wallet.json");
const TOKEN_PATH = join(process.cwd(), "keys/clockchain.token");
const REPO_SHA = process.env.HANDSHAKE_SHA ?? "0".repeat(40);
const FUND = parseEther("0.01");

// Human-paced: a stakeholder has to read a prompt, clone a repo and npm ci before
// they can even appear. Anything less than this and we would be timing out a
// person, which is exactly how the previous build died.
const WAIT_FOR_REQUESTOR_MS = 45 * 60_000;
const HEARTBEAT_MS = 20_000;

const publicClient = createPublicClient({ chain: sepolia, transport: http(RPC_URL) });

async function registerIdentity(account, treasuryAccount, label) {
  const treasuryWallet = createWalletClient({ account: treasuryAccount, chain: sepolia, transport: http(RPC_URL) });
  say("FUNDED", `Covering testnet gas so the ${label} can register an identity.`, { address: account.address });
  const fundTx = await treasuryWallet.sendTransaction({ to: account.address, value: FUND });
  await publicClient.waitForTransactionReceipt({ hash: fundTx, timeout: 180_000 });

  const own = createWalletClient({ account, chain: sepolia, transport: http(RPC_URL) });
  const tx = await own.writeContract({
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
  if (!agentId) stop("FAILED", `Could not read the ${label} identity id from the registry.`);
  say("IDENTITY_REGISTERED", `The ${label} now holds on-chain identity #${agentId}.`, {
    address: account.address, agentId,
  });
  return agentId;
}

/** Wait for a message kind, heartbeating so a watching audience sees liveness. */
async function awaitKind(sessionId, kind, budgetMs) {
  const deadline = Date.now() + budgetMs;
  let after = "0";
  let lastBeat = 0;
  while (Date.now() < deadline) {
    const got = await relay.pollMessages({ relayUrl: RELAY_URL, sessionId, after, waitMs: 20_000 });
    for (const message of got.messages ?? []) {
      after = message.seq;
      if (message.kind === kind) return message;
    }
    if (Date.now() - lastBeat > HEARTBEAT_MS) {
      lastBeat = Date.now();
      const mins = Math.round((deadline - Date.now()) / 60_000);
      say("REQUEST_SUBMITTED", `Still waiting for the requestor. ${mins} minutes remain in the window.`);
    }
  }
  stop("EXPIRED", "No requestor appeared before the session window closed.");
}

async function main() {
  say("SESSION_STARTED", "Starting a payment-authorization session. No money will move at any point.");

  const treasury = await openFundingWallet({ keystorePath: KEYSTORE });
  const token = (await readFile(TOKEN_PATH, "utf8")).trim();

  const payerKey = generatePrivateKey();
  const payerAccount = privateKeyToAccount(payerKey);
  const { privateKey: opPriv, publicKey: opPub } = generateKeyPairSync("ed25519");
  const operatorPrivateKeyPem = opPriv.export({ format: "pem", type: "pkcs8" });
  const repositoryPublicKey = opPub.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");

  const sessionId = crypto.randomUUID();
  await relay.createSession({ relayUrl: RELAY_URL, sessionId });

  // The discovery document is the ONLY thing a stakeholder receives. It is signed,
  // so everything downstream can be checked against the operator key rather than
  // trusted because the relay said so.
  const discovery = {
    schema: DISCOVERY_SCHEMA,
    sessionId,
    subjectRun: "stakeholder",
    protocolVersion: "1",
    relayUrl: RELAY_URL,
    kitRepoUrl: "https://github.com/thetangstr/clockchain-handshake-v2.git",
    repositorySha: REPO_SHA,
    operatorPublicKey: repositoryPublicKey,
    issuedAtMs: String(Date.now()),
    expiresAtMs: String(Date.now() + 45 * 60_000),
    paymentMoved: false,
  };
  await relay.createSession({ relayUrl: RELAY_URL, sessionId, discovery }).catch(() => {});
  await writeFile(join(process.cwd(), "runs", `discovery-${sessionId}.json`), JSON.stringify(discovery, null, 2)).catch(() => {});

  process.stdout.write(`\n${"=".repeat(64)}\nGive the stakeholder this, and nothing else:\n\n  Relay:   ${RELAY_URL}\n  Session: ${sessionId}\n\n${"=".repeat(64)}\n\n`);
  say("TERMS_PUBLISHED", "Session published. Waiting for the requestor to appear.");

  const claim = await awaitKind(sessionId, "identity_ready", WAIT_FOR_REQUESTOR_MS);
  const requestorAddress = claim.body.address;
  say("REQUEST_SUBMITTED", "A requestor appeared and asked to be paid.", { address: requestorAddress });

  // The requestor holds its own key, so it must sign its own registration. We
  // only pay for the gas — that is the entire extent of the operator's power over
  // the requestor's identity.
  const payerAgentId = await registerIdentity(payerAccount, treasury.account, "payer");

  const treasuryWallet = createWalletClient({ account: treasury.account, chain: sepolia, transport: http(RPC_URL) });
  say("FUNDED", "Covering the requestor's registration gas.", { address: requestorAddress });
  const fundTx = await treasuryWallet.sendTransaction({ to: requestorAddress, value: FUND });
  await publicClient.waitForTransactionReceipt({ hash: fundTx, timeout: 180_000 });

  const opKp = relay.generateEnvelopeKeyPair();
  await relay.postMessage({
    relayUrl: RELAY_URL, sessionId,
    envelope: relay.signEnvelope({
      sessionId, seq: "2", role: "payer", kind: "funding_record",
      body: { funded: requestorAddress.toLowerCase(), paymentMoved: false },
      senderKey: opKp.senderKey, privateKeyPem: opKp.privateKeyPem,
    }),
  });
  say("FUNDED", "The requestor is funded and is registering its own identity.");

  const ready = await awaitKind(sessionId, "party_ready", WAIT_FOR_REQUESTOR_MS);
  const requestorAgentId = String(ready.body.agentId);
  say("IDENTITY_REGISTERED", `The requestor registered on-chain identity #${requestorAgentId}.`);

  const { descriptor, mandateEnvelope, requestEnvelope } = await buildSession({
    payerAccount, payerAgentId,
    requestorAccount: { address: requestorAddress },
    requestorAgentId,
    repositorySha: REPO_SHA,
  });
  const envelope = createSignedEnvelope(descriptor, {
    keyId: "bilateral-demo-2026-07-28",
    privateKeyPem: operatorPrivateKeyPem,
  });

  await relay.postMessage({
    relayUrl: RELAY_URL, sessionId,
    envelope: relay.signEnvelope({
      sessionId, seq: "3", role: "payer", kind: "handshake_required",
      body: { descriptorEnvelope: envelope, repositoryPublicKey, paymentMoved: false },
      senderKey: opKp.senderKey, privateKeyPem: opKp.privateKeyPem,
    }),
  });
  say("HANDSHAKE_REQUIRED", "The payer requires a verified handshake before any payment is considered.");

  const root = await mkdtemp(join(tmpdir(), "handshake-op-"));
  const payerDirectory = join(root, "payer");
  await mkdir(payerDirectory, { mode: 0o700, recursive: true });
  await chmod(payerDirectory, 0o700);

  say("PROPOSED", "Opening the authorization window and recording the proposed terms.");
  await runPayerRole({
    client: createMcpClient({ token }),
    descriptorEnvelope: envelope,
    outputDirectory: payerDirectory,
    ownerOf: ({ agentId, registry }) =>
      publicClient.readContract({ abi: ERC8004_ABI, address: registry, args: [BigInt(agentId)], functionName: "ownerOf" }),
    repositoryPublicKey,
    signMessage: (bytes) => payerAccount.signMessage({ message: { raw: bytes } }),
  });
  say("ACKNOWLEDGED", "All three steps are recorded on Clockchain in order.");

  process.stdout.write("\nThe payer side is complete. Run the verifier to get the independent verdict.\n");
  process.stdout.write(`  Payer evidence: ${payerDirectory}\n`);
}

main().catch((error) => {
  if (process.env.HANDSHAKE_DEBUG) process.stderr.write(`${error?.stack}\n`);
  stop(error?.terminalCode ?? error?.code ?? "FAILED", error?.message ?? "The session stopped.");
});
