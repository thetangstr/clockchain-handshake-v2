#!/usr/bin/env node
/**
 * Clockchain Host.
 *
 * Publishes a signed discovery document to the relay, waits for the two parties
 * to bring their own keys and on-chain registrations, signs the session
 * descriptor as host, then verifies the evidence both parties upload.
 *
 * The host owns the treasury and descriptor key only. It never generates,
 * registers, or operates a payer identity.
 */
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createPublicClient, createWalletClient, http, parseEther } from "viem";
import { sepolia } from "viem/chains";

import * as relay from "../src/relay/client.mjs";
import {
  buildDescriptor, discoveryUrlFor, fetchDiscovery, postNext, readDiscovery,
  requestorPromptFor, stableDiscoveryUrl,
  say as logSay, DISCOVERY_SCHEMA,
} from "../src/roles/session.mjs";
import {
  SessionEnded,
  applyAnchorReport,
  awaitRoleMessages,
  downloadEvidencePackages,
  evidenceDeadlineAfterAnchorReport,
  fundIdentitySeats,
  mandateBodyFrom,
  remainingWaitMinutes,
  runHostLoop,
} from "../src/roles/host.mjs";
import { createMcpClient } from "../src/core/clockchain.mjs";
import { DESCRIPTOR_CHAIN_ID, REGISTRY_ADDRESS as CANONICAL_REGISTRY, createSignedEnvelope } from "../src/core/descriptor.mjs";
import { openFundingWallet } from "../src/core/funding/wallet.mjs";
import { ERC8004_ABI } from "../src/core/registration.mjs";
import { verifyBilateralAuthorization } from "../src/core/verdict.mjs";
import { buildSignedResult } from "../src/core/result.mjs";
import { RPC_URL } from "../src/core/constants.mjs";
import { transitionToAnchor } from "../src/monitor/anchor.mjs";
import { buildSnapshot, FAILED_STAGE, REASON_CODES, STATUSES } from "../src/monitor/snapshot.mjs";

const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i], process.argv[i + 1]);
const RELAY_URL = args.get("--relay-url") ?? process.env.HANDSHAKE_RELAY ?? "http://127.0.0.1:8080";
const KEYSTORE = args.get("--keystore") ?? join(process.cwd(), "keys/funding-wallet.json");
const TOKEN_PATH = join(process.cwd(), "keys/clockchain.token");
const REPO_SHA = process.env.HANDSHAKE_SHA ?? "0".repeat(40);
const KIT_REPO_URL = process.env.HANDSHAKE_KIT_REPO ?? "https://github.com/thetangstr/clockchain-handshake-v2.git";
const FUND = parseEther("0.01");

// Human-paced: stakeholders have to read prompts, clone repos and npm ci before
// they can even appear.
const WAIT_FOR_PARTIES_MS = 45 * 60_000;
const HEARTBEAT_MS = 20_000;
const ANCHOR_REPORT_BUDGET_MS = 12 * 60_000;
const EVIDENCE_AFTER_REPORT_MS = 5 * 60_000;
const SESSION_COOLDOWN_MS = 2_000;

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

/** Publish a final FAILED snapshot with the named public reason, then throw a
 * typed session ending so the host loop can open a fresh session. */
async function stop(reason, sentence) {
  await publishSnapshot(FAILED_STAGE, { reasonCode: reason });
  throw new SessionEnded(reason, sentence);
}

async function awaitOneRoleMessage(sessionId, { kind, role, after = "0", buffer = [], budgetMs = WAIT_FOR_PARTIES_MS }) {
  const result = await awaitRoleMessages({
    relayClient: relay,
    relayUrl: RELAY_URL,
    sessionId,
    kind,
    roles: [role],
    budgetMs,
    waitMs: 20_000,
    after,
    buffer,
    heartbeatMs: HEARTBEAT_MS,
    onHeartbeat: async ({ deadline, now }) => {
      const mins = remainingWaitMinutes({ deadline, now });
      await say("REQUEST_SUBMITTED", `Still waiting for ${role} ${kind}. ${mins} minutes remain in the window.`);
    },
  });
  return { after: result.after, buffer: result.buffer, message: result.messages[role] };
}

async function fundSeat({ treasuryWallet, sessionId, role, address, keyPair }) {
  await say("FUNDED", `Covering testnet gas so the ${role} can register an identity.`, { address });
  const fundTx = await treasuryWallet.sendTransaction({ to: address, value: FUND });
  await publicClient.waitForTransactionReceipt({ hash: fundTx, timeout: 180_000 });
  await postNext(relay, {
    relayUrl: RELAY_URL,
    sessionId,
    role: "host",
    kind: "funding_record",
    body: { funded: address.toLowerCase(), role, paymentMoved: false },
    keyPair,
  });
}

async function boot() {
  const treasury = await openFundingWallet({ keystorePath: KEYSTORE });
  const token = (await readFile(TOKEN_PATH, "utf8")).trim();
  return { token, treasury };
}

async function runOneSession({ token, treasury }) {
  monitorState = null;
  lastPublishedStage = null;
  logSay("SESSION_STARTED", "Starting a payment-authorization session. No money will move at any point.");

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
  await say("TERMS_PUBLISHED", "Session published. Waiting for the payer and requestor to appear.");

  const opKp = relay.generateEnvelopeKeyPair();
  const treasuryWallet = createWalletClient({ account: treasury.account, chain: sepolia, transport: http(RPC_URL) });

  const identityResult = await fundIdentitySeats({
    relayClient: relay,
    relayUrl: RELAY_URL,
    sessionId,
    roles: ["payer", "requestor"],
    budgetMs: WAIT_FOR_PARTIES_MS,
    waitMs: 20_000,
    fundSeat: async ({ role, message }) => {
      const address = String(message.body.address).toLowerCase();
      await fundSeat({ treasuryWallet, sessionId, role, address, keyPair: opKp });
    },
    heartbeatMs: HEARTBEAT_MS,
    onHeartbeat: async () => say("REQUEST_SUBMITTED", "Still waiting for both parties to bring their own identities."),
  }).catch((error) => stop(error?.code ?? "EXPIRED", error?.message ?? "The parties did not appear in time."));
  const identityReady = identityResult.messages;
  const payerAddress = String(identityReady.payer.body.address).toLowerCase();
  const requestorAddress = String(identityReady.requestor.body.address).toLowerCase();
  await say("REQUEST_SUBMITTED", "Both parties appeared with their own fresh identity keys.", {
    payer: payerAddress,
    requestor: requestorAddress,
  });

  monitorState.funding = { atMs: Date.now(), funded: true };
  await say("FUNDED", "Both parties are funded and registering their own identities.");

  const readyResult = await awaitRoleMessages({
    relayClient: relay,
    relayUrl: RELAY_URL,
    sessionId,
    kind: "party_ready",
    roles: ["payer", "requestor"],
    budgetMs: WAIT_FOR_PARTIES_MS,
    waitMs: 20_000,
    after: identityResult.after,
    buffer: identityResult.buffer,
    heartbeatMs: HEARTBEAT_MS,
    onHeartbeat: async () => say("IDENTITY_REGISTERED", "Still waiting for both parties to finish registration."),
  }).catch((error) => stop(error?.code ?? "EXPIRED", error?.message ?? "The parties did not finish registration in time."));
  const partyReady = readyResult.messages;
  const payerAgentId = String(partyReady.payer.body.agentId);
  const requestorAgentId = String(partyReady.requestor.body.agentId);
  if (monitorState) {
    monitorState.identities = {
      payer: { address: payerAddress, agentId: payerAgentId },
      payee: { address: requestorAddress, agentId: requestorAgentId },
    };
  }
  await say("IDENTITY_REGISTERED", "Both parties registered on-chain identities.");

  const mandateResult = await awaitOneRoleMessage(sessionId, {
    kind: "mandate",
    role: "payer",
    after: readyResult.after,
    buffer: readyResult.buffer,
  }).catch((error) => stop(error?.code ?? "EXPIRED", error?.message ?? "The payer mandate did not arrive in time."));
  const mandateBody = mandateBodyFrom(mandateResult.message);
  const { common, mandateEnvelope, sessionUuid } = mandateBody;
  await say("TERMS_PUBLISHED", "The payer published signed terms. Waiting for the requestor's signed request.");

  const submitted = await awaitOneRoleMessage(sessionId, {
    kind: "payment_request",
    role: "requestor",
    after: mandateResult.after,
    buffer: mandateResult.buffer,
  }).catch((error) => stop(error?.code ?? "EXPIRED", error?.message ?? "The payment request did not arrive in time."));
  const requestEnvelope = submitted.message.body.requestEnvelope;
  await say("REQUEST_SUBMITTED", "The requestor submitted a signed payment request against those terms.");

  const descriptor = buildDescriptor({ common, mandateEnvelope, requestEnvelope, repositorySha: REPO_SHA, sessionUuid });
  const envelope = createSignedEnvelope(descriptor, {
    keyId: "bilateral-demo-2026-07-28",
    privateKeyPem: operatorPrivateKeyPem,
  });

  await postNext(relay, {
    relayUrl: RELAY_URL, sessionId, role: "host", kind: "handshake_required",
    body: { descriptorEnvelope: envelope, repositoryPublicKey, paymentMoved: false },
    keyPair: opKp,
  });
  const handshakeRequiredAtMs = Date.now();
  await say("HANDSHAKE_REQUIRED", "The host requires a verified handshake before any payment is considered.");

  let evidenceDeadlineMs = handshakeRequiredAtMs + ANCHOR_REPORT_BUDGET_MS;
  try {
    const report = await awaitOneRoleMessage(sessionId, {
      kind: "anchor_report",
      role: "payer",
      after: submitted.after,
      buffer: submitted.buffer,
      budgetMs: ANCHOR_REPORT_BUDGET_MS,
    });
    const mapped = await applyAnchorReport({
      message: report.message,
      monitorState,
      relayUrl: RELAY_URL,
      say,
      transitionToAnchor,
    });
    if (mapped) {
      evidenceDeadlineMs = evidenceDeadlineAfterAnchorReport({
        mapped,
        originalDeadlineMs: evidenceDeadlineMs,
        nowMs: Date.now(),
        evidenceAfterReportMs: EVIDENCE_AFTER_REPORT_MS,
      });
    } else {
      await publishSnapshot("HANDSHAKE_REQUIRED");
    }
  } catch {
    await publishSnapshot("HANDSHAKE_REQUIRED");
  }

  const root = await mkdtemp(join(tmpdir(), "handshake-host-"));
  const { payerDirectory, payeeDirectory } = await downloadEvidencePackages({
    relayClient: relay,
    relayUrl: RELAY_URL,
    sessionId,
    root,
    deadlineMs: evidenceDeadlineMs,
    onWaiting: async () => say("EVIDENCE_RECEIVED", "Waiting for both parties' evidence to arrive."),
  }).catch((error) => stop(error?.code ?? "MISSING", error?.message ?? "Both evidence packages did not arrive in time."));
  bumpHeartbeat("payer", "payee");
  await say("EVIDENCE_RECEIVED", "Both parties' evidence has arrived. Verifying now, while the window is open.");

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
  // covered the publish, and a run the verifier had already passed exited
  // as Stopped.
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
          address: payerAddress.toLowerCase(),
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

async function main() {
  await runHostLoop({
    boot,
    cooldownMs: SESSION_COOLDOWN_MS,
    onError: async (error) => {
      if (process.env.HANDSHAKE_DEBUG) process.stderr.write(`${error?.stack ?? error}\n`);
      const code = error?.terminalCode ?? error?.code ?? "FAILED";
      const message = error?.message ?? "The session stopped.";
      process.stderr.write(`${JSON.stringify({ reason: code, message, paymentMoved: false })}\n`);
    },
    runOneSession: async ({ bootResult }) => runOneSession(bootResult),
  });
}

main().catch((error) => {
  if (process.env.HANDSHAKE_DEBUG) process.stderr.write(`${error?.stack ?? error}\n`);
  process.stderr.write(`${JSON.stringify({ reason: error?.code ?? "FAILED", message: error?.message ?? "Host boot failed.", paymentMoved: false })}\n`);
  process.exitCode = 1;
});
