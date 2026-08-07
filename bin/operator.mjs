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
  requestorPromptFor, stableDiscoveryUrl,
  say as logSay, stop as stopSession, DISCOVERY_SCHEMA,
} from "../src/roles/session.mjs";
import { createMcpClient } from "../src/core/clockchain.mjs";
import { DESCRIPTOR_CHAIN_ID, REGISTRY_ADDRESS as CANONICAL_REGISTRY, createSignedEnvelope } from "../src/core/descriptor.mjs";
import { openFundingWallet } from "../src/core/funding/wallet.mjs";
import { ERC8004_ABI } from "../src/core/registration.mjs";
import { runPayerRole } from "../src/core/roles-core.mjs";
import { verifyBilateralAuthorization } from "../src/core/verdict.mjs";
import { buildSignedResult } from "../src/core/result.mjs";
import { REGISTRY_ADDRESS, RPC_URL } from "../src/core/constants.mjs";
import { buildSnapshot, FAILED_STAGE, REASON_CODES, STATUSES } from "../src/monitor/snapshot.mjs";

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

// --- Monitor snapshot publication -------------------------------------
//
// Best-effort narration for the stakeholder audience page (see
// src/monitor/snapshot.mjs and src/monitor/stakeholder/*). "Best-effort"
// means exactly what it says: a relay hiccup here degrades what an audience
// can see, never whether the protocol itself completes or how it reports a
// failure. The verdict field is set ONLY in one place below, from the
// verifier's own return value -- nothing here may guess it earlier.
const SNAPSHOT_PUBLISH_BUDGET_MS = 5_000;

let monitorState = null;
let lastPublishedStage = null;

function createMonitorState(sid) {
  return {
    anchors: { acceptance: null, acknowledgment: null, proposal: null },
    funding: null,
    identities: null,
    heartbeat: { payee: null, payer: null, verifier: null },
    sessionId: sid,
    stageHistory: [],
    verdict: null,
  };
}

function bumpHeartbeat(...roles) {
  if (!monitorState) return;
  const lastSeenMs = Date.now();
  for (const role of roles) monitorState.heartbeat[role] = { lastSeenMs };
}

function transitionToAnchor(kind, transition) {
  return {
    blockHeight: transition.onChain.blockHeight,
    blockTime: Number(transition.blockTimeMs),
    // Clockchain has no public explorer: mcp.clockchain.network answers 401 on
    // every path except /health, and it advertises only a token endpoint. The
    // URL this used to build -- MCP_BASE_URL/explorer/{kind}/{ledgerId} -- was
    // our own invention for a route that has never existed, and the audience
    // page linked it, so every "check this receipt" link on the projector led
    // to an auth error. Point at the relay's own re-read, which resolves.
    explorerUrl: `${RELAY_URL.replace(/\/+$/, "")}/v1/blocks/${transition.onChain.blockHeight}`,
    kind,
    ledgerId: transition.onChain.ledgerId,
    receipt: {
      anchoredHash: transition.onChain.anchoredHash,
      blockTimeRaw: transition.blockTimeRaw,
      digest: transition.digest,
    },
    // Who signed this transition. The payer writes the proposal and the
    // acknowledgement while watching for the acceptance; the payee does the
    // inverse (src/core/roles-core.mjs).
    signedBy: signerOf(kind, transition.message),
    // The terms as signed. This was being thrown away: transitionToAnchor kept
    // six fields and discarded the message, so the board could show that a
    // receipt existed but not what it said.
    terms: termsOf(transition.message),
  };
}

function signerOf(kind, message) {
  const party = kind === "acceptance" ? message?.payee : message?.payer;
  if (!party?.address || !party?.agentId) return null;
  return { address: String(party.address).toLowerCase(), agentId: String(party.agentId) };
}

function termsOf(message) {
  if (!message?.amount) return null;
  return {
    currency: String(message.amount.currency),
    expirySeconds: String(message.expirySeconds),
    // The predecessor is a triple pointing at the previous receipt
    // ({anchoredHash, blockHeight, kind, ledgerId}); its block height is the
    // half a reader can act on. Stringifying the object gave "[object Object]",
    // which reached a live board before a real run caught it.
    predecessor: message.predecessor?.blockHeight
      ? String(message.predecessor.blockHeight)
      : null,
    sequence: String(message.sequence),
    sessionDigest: String(message.sessionDigest),
    value: String(message.amount.value),
  };
}

async function publishSnapshot(stage, { reasonCode = null } = {}) {
  if (!monitorState) return;
  const nowMs = Date.now();
  if (stage !== lastPublishedStage) {
    monitorState.stageHistory = [
      ...monitorState.stageHistory,
      { atMs: nowMs, status: stage },
    ];
    lastPublishedStage = stage;
  }
  const safeReasonCode =
    stage === FAILED_STAGE
      ? (REASON_CODES.includes(reasonCode) ? reasonCode : "FAILED")
      : null;
  let snapshot;
  try {
    snapshot = buildSnapshot({
      anchors: monitorState.anchors,
      currentStage: stage,
      funding: monitorState.funding,
      heartbeat: monitorState.heartbeat,
      identities: monitorState.identities,
      reasonCode: safeReasonCode,
      sessionId: monitorState.sessionId,
      stageHistory: monitorState.stageHistory,
      subjectRun: "stakeholder",
      updatedAtMs: nowMs,
      verdict: monitorState.verdict,
    });
  } catch {
    // A local snapshot-shape bug must never take down the run it only
    // narrates.
    return;
  }
  try {
    await relay.putSnapshot({
      relayUrl: RELAY_URL,
      sessionId: monitorState.sessionId,
      snapshot,
      retryBudgetMs: SNAPSHOT_PUBLISH_BUDGET_MS,
    });
  } catch {
    // Same: audience visibility is best-effort, never a run-blocking
    // dependency.
  }
}

/** Narrate to the CLI (unchanged behaviour) and, once a session exists,
 * publish the matching monitor snapshot. Shadows the imported `say` so every
 * existing call site gets this for free. */
async function say(stage, sentence, extra = {}) {
  logSay(stage, sentence, extra);
  if (STATUSES.includes(stage)) {
    bumpHeartbeat("payer");
    await publishSnapshot(stage);
  }
}

/** Publish a final FAILED snapshot with the named public reason, then close
 * exactly as the imported stop() always has. Shadows the imported `stop` so
 * every existing call site gets this for free. */
async function stop(reason, sentence) {
  await publishSnapshot(FAILED_STAGE, { reasonCode: reason });
  stopSession(reason, sentence);
}

async function registerIdentity(account, treasuryAccount, label) {
  const treasuryWallet = createWalletClient({ account: treasuryAccount, chain: sepolia, transport: http(RPC_URL) });
  await say("FUNDED", `Covering testnet gas so the ${label} can register an identity.`, { address: account.address });
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
  if (!agentId) await stop("FAILED", `Could not read the ${label} identity id from the registry.`);
  await say("IDENTITY_REGISTERED", `The ${label} now holds on-chain identity #${agentId}.`, {
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
      // Any traffic on this session from the counterparty is a real liveness
      // signal for the payee -- distinct from our own heartbeat narration
      // below, which only proves the operator process is still polling.
      bumpHeartbeat("payee");
      if (message.kind === kind) return message;
    }
    if (Date.now() - lastBeat > HEARTBEAT_MS) {
      lastBeat = Date.now();
      const mins = Math.round((deadline - Date.now()) / 60_000);
      await say("REQUEST_SUBMITTED", `Still waiting for the requestor. ${mins} minutes remain in the window.`);
    }
  }
  await stop("EXPIRED", "No requestor appeared before the session window closed.");
}

async function main() {
  logSay("SESSION_STARTED", "Starting a payment-authorization session. No money will move at any point.");

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
  if (!selfCheck.ok) await stop(selfCheck.reason, `Refusing to publish an invitation the kit would reject: ${selfCheck.sentence}`);

  await relay.createSession({ relayUrl: RELAY_URL, sessionId, discovery });
  // The session now exists on the relay -- from here on a monitor snapshot
  // has somewhere to live, so every subsequent say() also publishes one.
  monitorState = createMonitorState(sessionId);
  await publishSnapshot("SESSION_STARTED");
  await writeFile(join(process.cwd(), "runs", `discovery-${sessionId}.json`), JSON.stringify(discovery, null, 2)).catch(() => {});

  // Read it back through the same URL the stakeholder will use. Handing over a
  // link that does not resolve is the one failure they cannot diagnose.
  const discoveryUrl = discoveryUrlFor({ relayUrl: RELAY_URL, sessionId });
  const served = await fetchDiscovery({ discoveryUrl, budgetMs: 60_000 });
  if (!served.ok) await stop(served.reason, `The invitation link did not read back cleanly: ${served.sentence}`);

  process.stdout.write(
    `\n${"=".repeat(70)}\n` +
    `SEND THIS WHOLE BLOCK TO THE STAKEHOLDER. They paste it as-is —\n` +
    `there is nothing for them to fill in or edit.\n` +
    `${"=".repeat(70)}\n\n` +
    `${requestorPromptFor(stableDiscoveryUrl(RELAY_URL))}\n\n` +
    `${"=".repeat(70)}\n\n`,
  );
  const relayBase = RELAY_URL.replace(/\/+$/, "");
  process.stdout.write(
    `Put this on the projector. The link is permanent — it always follows the\n` +
    `newest run, so it can be opened before the audience arrives:\n\n` +
    `  ${relayBase}/monitor/current\n\n` +
    `  (this run specifically: ${relayBase}/monitor/${encodeURIComponent(sessionId)})\n\n`,
  );
  await say("TERMS_PUBLISHED", "Session published. Waiting for the requestor to appear.");

  const claim = await awaitKind(sessionId, "identity_ready", WAIT_FOR_REQUESTOR_MS);
  const requestorAddress = claim.body.address;
  await say("REQUEST_SUBMITTED", "A requestor appeared and asked to be paid.", { address: requestorAddress });

  // The requestor holds its own key, so it must sign its own registration. We
  // only pay for the gas — that is the entire extent of the operator's power over
  // the requestor's identity.
  const payerAgentId = await registerIdentity(payerAccount, treasury.account, "payer");

  const treasuryWallet = createWalletClient({ account: treasury.account, chain: sepolia, transport: http(RPC_URL) });
  await say("FUNDED", "Covering the requestor's registration gas.", { address: requestorAddress });
  const fundTx = await treasuryWallet.sendTransaction({ to: requestorAddress, value: FUND });
  await publicClient.waitForTransactionReceipt({ hash: fundTx, timeout: 180_000 });

  const opKp = relay.generateEnvelopeKeyPair();
  await postNext(relay, { relayUrl: RELAY_URL, sessionId, role: "payer", kind: "funding_record", body: { funded: requestorAddress.toLowerCase(), paymentMoved: false }, keyPair: opKp });
  monitorState.funding = { atMs: Date.now(), funded: true };
  await say("FUNDED", "The requestor is funded and is registering its own identity.");

  const ready = await awaitKind(sessionId, "party_ready", WAIT_FOR_REQUESTOR_MS);
  const requestorAgentId = String(ready.body.agentId);
  // Both sides now hold an ERC-8004 registration, so the board can show what
  // the registry itself returned while the run is still going.
  if (monitorState) {
    monitorState.identities = {
      payer: { address: payerAccount.address.toLowerCase(), agentId: String(payerAgentId) },
      payee: { address: requestorAddress.toLowerCase(), agentId: String(requestorAgentId) },
    };
  }
  await say("IDENTITY_REGISTERED", `The requestor registered on-chain identity #${requestorAgentId}.`);

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
  await say("TERMS_PUBLISHED", "Signed payment terms published. Waiting for the requestor to submit its request.");

  const submitted = await awaitKind(sessionId, "payment_request", WAIT_FOR_REQUESTOR_MS);
  const requestEnvelope = submitted.body.requestEnvelope;
  await say("REQUEST_SUBMITTED", "The requestor submitted a signed payment request against those terms.");

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
  await say("HANDSHAKE_REQUIRED", "The payer requires a verified handshake before any payment is considered.");

  await awaitKind(sessionId, "watching", WAIT_FOR_REQUESTOR_MS);
  await say("REQUEST_SUBMITTED", "The requestor is watching the ledger. Opening the window now.");

  const root = await mkdtemp(join(tmpdir(), "handshake-op-"));
  const payerDirectory = join(root, "payer");
  await mkdir(payerDirectory, { mode: 0o700, recursive: true });
  await chmod(payerDirectory, 0o700);

  await say("PROPOSED", "Opening the authorization window and recording the proposed terms.");
  // runPayerRole blocks until all three transitions (proposal, acceptance,
  // acknowledgment) are anchored -- there is no mid-poll hook to narrate
  // ACCEPTED the instant it lands on-chain, so it is narrated immediately
  // after, using the real anchors this call already produced rather than a
  // guess made before they existed.
  const payerResult = await runPayerRole({
    client: createMcpClient({ token }),
    descriptorEnvelope: envelope,
    outputDirectory: payerDirectory,
    ownerOf: ({ agentId, registry }) =>
      publicClient.readContract({ abi: ERC8004_ABI, address: registry, args: [BigInt(agentId)], functionName: "ownerOf" }),
    repositoryPublicKey,
    signMessage: (bytes) => payerAccount.signMessage({ message: { raw: bytes } }),
  });
  const [proposedTransition, acceptedTransition, acknowledgedTransition] = payerResult.transitions;
  monitorState.anchors = {
    ...monitorState.anchors,
    acceptance: transitionToAnchor("acceptance", acceptedTransition),
    proposal: transitionToAnchor("proposal", proposedTransition),
  };
  bumpHeartbeat("payee");
  await say("ACCEPTED", "The requestor accepted the exact terms, and that acceptance is recorded.");
  monitorState.anchors = {
    ...monitorState.anchors,
    acknowledgment: transitionToAnchor("acknowledgment", acknowledgedTransition),
  };
  await say("ACKNOWLEDGED", "All three steps are recorded on Clockchain in order.");

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
    await say("EVIDENCE_RECEIVED", "Waiting for the requestor's evidence to arrive.");
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  if (!parts?.json) await stop("MISSING", "The requestor's evidence did not arrive in time.");
  bumpHeartbeat("payee");
  await writeFile(join(payeeDirectory, "party-result.json"), parts.json);
  await writeFile(join(payeeDirectory, "PARTY-RESULT.md"), parts.markdown);
  await writeFile(join(payeeDirectory, ".party-result.complete.json"), parts.marker);
  await say("EVIDENCE_RECEIVED", "The requestor's evidence has arrived. Verifying now, while the window is open.");

  await say("VERIFYING", "An independent verifier is re-checking every piece of evidence from scratch.");
  bumpHeartbeat("verifier");
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
  // The single most important line in this file: the monitor's verdict field
  // is set HERE and ONLY here, from the independent verifier's own return
  // value, after it has actually run -- never before, never guessed.
  bumpHeartbeat("verifier");
  monitorState.verdict = { outcome: verdict.outcome, paymentMoved: verdict.paymentMoved };
  await publishSnapshot("VERIFYING");
  process.stdout.write(`\nVerifier outcome: ${verdict.outcome}\nNo money moved: ${verdict.paymentMoved === false}\n`);
  for (const t of verdict.transitions ?? []) {
    process.stdout.write(`  ${t.kind}  block ${t.blockHeight}  ledger ${t.ledgerId}\n`);
  }

  // The closing certificate: the verifier's words, signed with the same
  // operator key that signed the descriptor, published to the relay so BOTH
  // parties fetch the same artifact. Every value is the verifier's own return
  // -- outcome, sessionDigest, transitions -- none is restated or improved.
  //
  // The ENTIRE section is guarded, construction included. The first live run
  // of this path proved why: identityReference threw on a string agent id
  // AFTER the verdict had printed, the exception escaped a guard that only
  // covered the publish, and a verified AUTHORIZED run exited as Stopped.
  // Nothing on the certificate path may ever demote a verified run.
  let resultEnvelope = null;
  try {
    resultEnvelope = buildSignedResult({
      issuedAtMs: String(Date.now()),
      keyId: "bilateral-demo-2026-07-28",
      parties: {
        payee: {
          address: requestorAddress.toLowerCase(),
          agentId: String(requestorAgentId),
          // Built from descriptor.mjs exports -- the LOWERCASE registry the
          // canonical signed path uses. registration.mjs has a checksummed
          // twin of this constant, and a checksummed address is rejected by
          // the canonical profile at signing time.
          reference: `eip155:${DESCRIPTOR_CHAIN_ID}:${CANONICAL_REGISTRY}:${requestorAgentId}`,
        },
        payer: {
          address: payerAccount.address.toLowerCase(),
          agentId: String(payerAgentId),
          reference: `eip155:${DESCRIPTOR_CHAIN_ID}:${CANONICAL_REGISTRY}:${payerAgentId}`,
        },
      },
      privateKeyPem: operatorPrivateKeyPem,
      sessionDigest: verdict.sessionDigest,
      sessionId,
      verdict,
    });
    await relay.putResult({
      relayUrl: RELAY_URL,
      sessionId,
      envelope: resultEnvelope,
      retryBudgetMs: 30_000,
    });
    process.stdout.write(
      "\nClosing certificate published. Both parties can fetch it from the\n" +
      "session and verify it against the operator key the descriptor named.\n",
    );
  } catch (error) {
    process.stdout.write(
      `\nCERTIFICATE_NOT_ISSUED: the closing certificate could not be ` +
      `${resultEnvelope === null ? "built" : "published"}\n` +
      `(${error?.code ?? error?.message ?? "unknown"}). The verdict above stands; whatever was\n` +
      `produced is preserved in runs/session-${sessionId}.json.\n`,
    );
  }

  await writeFile(join(process.cwd(), "runs", `session-${sessionId}.json`),
    JSON.stringify({ descriptorEnvelope: envelope, mandateEnvelope, requestEnvelope, repositoryPublicKey, payerDirectory, payeeDirectory, outcome: verdict.outcome, anchors: verdict.transitions, resultEnvelope, paymentMoved: false }, null, 2));
  process.stdout.write(
    `\nThe run is complete and the verdict above came from the independent verifier.\n` +
    `Anyone can re-check those three blocks themselves; no money moved at any point.\n` +
    `  Evidence: ${payerDirectory}\n`,
  );
}

main().catch(async (error) => {
  if (process.env.HANDSHAKE_DEBUG) process.stderr.write(`${error?.stack}\n`);
  await stop(error?.terminalCode ?? error?.code ?? "FAILED", error?.message ?? "The session stopped.");
});
