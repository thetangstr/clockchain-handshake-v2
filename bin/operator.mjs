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
import {
  buildDescriptor, buildMandate, discoveryUrlFor, fetchDiscovery, postNext, readDiscovery,
  say, stop, DISCOVERY_SCHEMA,
} from "../src/roles/session.mjs";
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
const KIT_REPO_URL = process.env.HANDSHAKE_KIT_REPO ?? "https://github.com/thetangstr/clockchain-handshake-v2.git";
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

  // The discovery document is the ONLY thing a stakeholder receives, so it has to
  // be published in the same call that opens the session — the relay refuses a
  // second registration for the same id, and a session without a discovery
  // document is a session nobody can join from one pasted link.
  const publishedAtMs = Date.now();
  const discovery = {
    schema: DISCOVERY_SCHEMA,
    sessionId,
    subjectRun: "stakeholder",
    protocolVersion: "1",
    relayUrl: RELAY_URL,
    kitRepoUrl: KIT_REPO_URL,
    repositorySha: REPO_SHA,
    operatorPublicKey: repositoryPublicKey,
    issuedAtMs: String(publishedAtMs),
    // >= 30 minutes: a person has to read a prompt, clone and install before they
    // can appear at all, and the kit refuses anything shorter as malformed.
    expiresAtMs: String(publishedAtMs + 45 * 60_000),
    paymentMoved: false,
  };
  const selfCheck = readDiscovery(discovery, { now: publishedAtMs });
  if (!selfCheck.ok) stop(selfCheck.reason, `Refusing to publish an invitation the kit would reject: ${selfCheck.sentence}`);

  await relay.createSession({ relayUrl: RELAY_URL, sessionId, discovery });
  await writeFile(join(process.cwd(), "runs", `discovery-${sessionId}.json`), JSON.stringify(discovery, null, 2)).catch(() => {});

  // Read it back through the same URL the stakeholder will use. Handing over a
  // link that does not resolve is the one failure they cannot diagnose.
  const discoveryUrl = discoveryUrlFor({ relayUrl: RELAY_URL, sessionId });
  const served = await fetchDiscovery({ discoveryUrl, budgetMs: 60_000 });
  if (!served.ok) stop(served.reason, `The invitation link did not read back cleanly: ${served.sentence}`);

  process.stdout.write(
    `\n${"=".repeat(64)}\nGive the stakeholder this one line, and nothing else:\n\n` +
    `${discoveryUrl}\n\n${"=".repeat(64)}\n\n`,
  );
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
  await postNext(relay, { relayUrl: RELAY_URL, sessionId, role: "payer", kind: "funding_record", body: { funded: requestorAddress.toLowerCase(), paymentMoved: false }, keyPair: opKp });
  say("FUNDED", "The requestor is funded and is registering its own identity.");

  const ready = await awaitKind(sessionId, "party_ready", WAIT_FOR_REQUESTOR_MS);
  const requestorAgentId = String(ready.body.agentId);
  say("IDENTITY_REGISTERED", `The requestor registered on-chain identity #${requestorAgentId}.`);

  // The payer signs the mandate. It cannot sign the payment request — that
  // signature must come from the requestor's own key, which lives on the
  // requestor's machine and never leaves it. So publish the terms and wait.
  const { common, expiresAtMs, issuedAtMs, mandateEnvelope, sessionUuid } = await buildMandate({
    payerAccount, payerAgentId, requestorAddress, requestorAgentId, repositorySha: REPO_SHA,
  });
  await postNext(relay, {
    relayUrl: RELAY_URL, sessionId, role: "payer", kind: "mandate",
    body: { common, expiresAtMs: String(expiresAtMs), issuedAtMs: String(issuedAtMs), mandateEnvelope, sessionUuid, paymentMoved: false },
    keyPair: opKp,
  });
  say("TERMS_PUBLISHED", "Signed payment terms published. Waiting for the requestor to submit its request.");

  const submitted = await awaitKind(sessionId, "payment_request", WAIT_FOR_REQUESTOR_MS);
  const requestEnvelope = submitted.body.requestEnvelope;
  say("REQUEST_SUBMITTED", "The requestor submitted a signed payment request against those terms.");

  const descriptor = buildDescriptor({ common, mandateEnvelope, requestEnvelope, repositorySha: REPO_SHA, sessionUuid });
  const envelope = createSignedEnvelope(descriptor, {
    keyId: "bilateral-demo-2026-07-28",
    privateKeyPem: operatorPrivateKeyPem,
  });

  await postNext(relay, {
    relayUrl: RELAY_URL, sessionId, role: "payer", kind: "handshake_required",
    body: { descriptorEnvelope: envelope, repositoryPublicKey, paymentMoved: false },
    keyPair: opKp,
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

  const payeeDirectory = join(root, "payee");
  await mkdir(payeeDirectory, { mode: 0o700, recursive: true });
  await chmod(payeeDirectory, 0o700);
  // The requestor uploads its package as it finishes; we may arrive first. Poll
  // rather than assume — but stay well inside the anchor window.
  let parts = null;
  const evidenceDeadline = Date.now() + 4 * 60_000;
  while (Date.now() < evidenceDeadline) {
    try {
      parts = await relay.getEvidence({ relayUrl: RELAY_URL, sessionId, role: "payee" });
      if (parts?.json) break;
    } catch { /* not uploaded yet */ }
    say("EVIDENCE_RECEIVED", "Waiting for the requestor's evidence to arrive.");
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  if (!parts?.json) stop("MISSING", "The requestor's evidence did not arrive in time.");
  await writeFile(join(payeeDirectory, "party-result.json"), parts.json);
  await writeFile(join(payeeDirectory, "PARTY-RESULT.md"), parts.markdown);
  await writeFile(join(payeeDirectory, ".party-result.complete.json"), parts.marker);
  say("EVIDENCE_RECEIVED", "The requestor's evidence has arrived. Verifying now, while the window is open.");

  say("VERIFYING", "An independent verifier is re-checking every piece of evidence from scratch.");
  const verdict = await verifyBilateralAuthorization({
    clockchain: createMcpClient({ token }),
    descriptorEnvelope: envelope,
    mandateEnvelope,
    ownerOf: ({ agentId, registry }) =>
      publicClient.readContract({ abi: ERC8004_ABI, address: registry, args: [BigInt(agentId)], functionName: "ownerOf" }),
    payerDirectory,
    payeeDirectory,
    requestEnvelope,
    repositoryPublicKeyResolver: async () => repositoryPublicKey,
  });
  process.stdout.write(`\nVerifier outcome: ${verdict.outcome}\nNo money moved: ${verdict.paymentMoved === false}\n`);
  for (const t of verdict.transitions ?? []) {
    process.stdout.write(`  ${t.kind}  block ${t.blockHeight}  ledger ${t.ledgerId}\n`);
  }

  await writeFile(join(process.cwd(), "runs", `session-${sessionId}.json`),
    JSON.stringify({ descriptorEnvelope: envelope, mandateEnvelope, requestEnvelope, repositoryPublicKey, payerDirectory, payeeDirectory, outcome: verdict.outcome, anchors: verdict.transitions, paymentMoved: false }, null, 2));
  process.stdout.write("\nThe payer side is complete. Run the verifier to get the independent verdict.\n");
  process.stdout.write(`  Payer evidence: ${payerDirectory}\n`);
}

main().catch((error) => {
  if (process.env.HANDSHAKE_DEBUG) process.stderr.write(`${error?.stack}\n`);
  stop(error?.terminalCode ?? error?.code ?? "FAILED", error?.message ?? "The session stopped.");
});
