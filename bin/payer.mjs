#!/usr/bin/env node
/**
 * The Payer kit — the payer-side thing a stakeholder runs.
 *
 * It receives ONE URL and nothing else: no session id to copy by hand and no
 * relay override. It fetches the invitation behind that URL, checks it,
 * generates its own keypair, registers its own on-chain identity, publishes
 * signed payment terms, records the payer side of the handshake, and uploads
 * its evidence. It never claims the run succeeded — only the operator's
 * independent verifier can say that.
 */
import { chmod, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createPublicClient, createWalletClient, http } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";

import * as relay from "../src/relay/client.mjs";
import { buildMandate, fetchDiscovery, postNext, readDiscovery, roleAlreadySeated, say, stop } from "../src/roles/session.mjs";
import { verifyResultEnvelope } from "../src/core/result.mjs";
import { createMcpClient, mintDemoToken } from "../src/core/clockchain.mjs";
import { ERC8004_ABI } from "../src/core/registration.mjs";
import { runPayerRole } from "../src/core/roles-core.mjs";
import { REGISTRY_ADDRESS, RPC_URL } from "../src/core/constants.mjs";
import { transitionToAnchor, anchorToWireReport } from "../src/monitor/anchor.mjs";
import { selectFundingRecord } from "../src/roles/funding-selection.mjs";
import { assertHandshakeRepositoryKey, issuedAtMsFromLedgerTimestamp, selectRequestorRoster } from "../src/roles/payer.mjs";

const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i], process.argv[i + 1]);
const DISCOVERY_URL = args.get("--discovery-url") ?? process.env.HANDSHAKE_DISCOVERY ?? null;

let RELAY_URL = null;
let SESSION_ID = null;
let DISCOVERY = null;

async function resolveRendezvous() {
  if (args.has("--relay-url")) {
    stop("MALFORMED", "This needs one thing: --discovery-url followed by the link the host gave you.");
  }
  if (!DISCOVERY_URL) {
    stop("MALFORMED", "This needs one thing: --discovery-url followed by the link the host gave you.");
  }
  say("SESSION_STARTED", "Opening the host's link.");
  const found = await fetchDiscovery({
    discoveryUrl: DISCOVERY_URL,
    onHeartbeat: () => say("SESSION_STARTED", "Still trying the host's link. No money has moved."),
  });
  if (!found.ok) stop(found.reason, found.sentence);
  const checked = readDiscovery(found.discovery);
  if (!checked.ok) stop(checked.reason, checked.sentence);
  DISCOVERY = checked.discovery;
  RELAY_URL = DISCOVERY.relayUrl;
  SESSION_ID = DISCOVERY.sessionId;
  say("SESSION_STARTED", "The link checks out. Joining the host's session.", {
    sessionId: SESSION_ID,
  });
}

// Human-paced throughout: the host has to fund us and the requestor has to
// appear from the mailbox before the first anchor opens the timed window.
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
      say("REQUEST_SUBMITTED", "Still working — waiting on the host. No money has moved.");
    }
  }
  stop("EXPIRED", "The host did not respond before the session window closed.");
}

async function awaitRequestorRoster(budgetMs, after = "0") {
  const deadline = Date.now() + budgetMs;
  let cursor = after;
  let lastBeat = 0;
  let roster = selectRequestorRoster([]);
  while (Date.now() < deadline) {
    const got = await relay.pollMessages({
      relayUrl: RELAY_URL, sessionId: SESSION_ID, after: cursor, waitMs: 20_000,
    });
    for (const message of got.messages ?? []) {
      cursor = message.seq;
    }
    roster = selectRequestorRoster(got.messages, roster);
    if (roster.ready) {
      return { identityReady: roster.identityReady, partyReady: roster.partyReady };
    }
    if (Date.now() - lastBeat > HEARTBEAT_MS) {
      lastBeat = Date.now();
      say("REQUEST_SUBMITTED", "Still working — waiting on the requestor. No money has moved.");
    }
  }
  stop("EXPIRED", "The requestor did not respond before the session window closed.");
}

async function awaitFundingRecord(address, budgetMs, after = "0") {
  const deadline = Date.now() + budgetMs;
  let cursor = after;
  let lastBeat = 0;
  while (Date.now() < deadline) {
    const got = await relay.pollMessages({
      relayUrl: RELAY_URL, sessionId: SESSION_ID, after: cursor, waitMs: 20_000,
    });
    for (const message of got.messages ?? []) {
      cursor = message.seq;
    }
    const selected = selectFundingRecord(got.messages, { address, role: "payer" });
    if (selected.status === "proceed") return selected.message;
    if (selected.status === "already-bound") {
      stop("ROLE_ALREADY_BOUND",
        "The host funded a different payer: another agent claimed this session first. Nothing was spent.");
    }
    if (Date.now() - lastBeat > HEARTBEAT_MS) {
      lastBeat = Date.now();
      say("REQUEST_SUBMITTED", "Still working — waiting on the host. No money has moved.");
    }
  }
  stop("EXPIRED", "The host did not respond before the session window closed.");
}

function anchorReportFrom(transitions) {
  const [proposal, acceptance, acknowledgment] = transitions;
  return {
    acknowledgment: anchorToWireReport(transitionToAnchor("acknowledgment", acknowledgment, { relayUrl: RELAY_URL })),
    acceptance: anchorToWireReport(transitionToAnchor("acceptance", acceptance, { relayUrl: RELAY_URL })),
    proposal: anchorToWireReport(transitionToAnchor("proposal", proposal, { relayUrl: RELAY_URL })),
  };
}

async function main() {
  await resolveRendezvous();
  say("SESSION_STARTED", "Asking to authorize a payment. This is a verification exercise: no money will move.");

  const seated = await relay.pollMessages({
    relayUrl: RELAY_URL, sessionId: SESSION_ID, after: "0", waitMs: 0,
  });
  if (roleAlreadySeated(seated.messages, "payer")) {
    stop("ROLE_ALREADY_BOUND",
      "Another payer already joined this session. Only one can authorize per session — ask the host to open a fresh one.");
  }

  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  const kp = relay.generateEnvelopeKeyPair();
  say("REQUEST_SUBMITTED", "Generated a fresh identity key for this run.", { address: account.address });

  await postNext(relay, { relayUrl: RELAY_URL, sessionId: SESSION_ID, role: "payer", kind: "identity_ready", body: { address: account.address.toLowerCase(), paymentMoved: false }, keyPair: kp });
  say("HANDSHAKE_REQUIRED",
    "The host will not consider this session without a verified handshake first. Following its instructions.");

  const funding = await awaitFundingRecord(account.address, WAIT_MS);
  if (String(funding.body?.funded ?? "").toLowerCase() !== account.address.toLowerCase()) {
    stop("ROLE_ALREADY_BOUND",
      "The host funded a different payer: another agent claimed this session first. Nothing was spent.");
  }
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

  await postNext(relay, { relayUrl: RELAY_URL, sessionId: SESSION_ID, role: "payer", kind: "party_ready", body: { address: account.address.toLowerCase(), agentId, paymentMoved: false }, keyPair: kp });

  const { identityReady: requestorIdentity, partyReady: requestorParty } = await awaitRequestorRoster(WAIT_MS);
  const requestorAddress = String(requestorIdentity.body?.address ?? "").toLowerCase();
  const requestorAgentId = String(requestorParty.body?.agentId ?? "");
  if (!requestorAddress || !requestorAgentId) {
    stop("MALFORMED", "The requestor identity was incomplete.");
  }
  say("IDENTITY_REGISTERED", "The requestor registered an on-chain identity.", {
    agentId: requestorAgentId,
    requestor: requestorAddress,
  });

  const token = await mintDemoToken({});
  const clockchain = createMcpClient({ token });
  const issuedAtMs = issuedAtMsFromLedgerTimestamp(await clockchain.getTimestamp());
  const mandate = await buildMandate({
    issuedAtMs,
    payerAccount: account,
    payerAgentId: agentId,
    requestorAddress,
    requestorAgentId,
    repositorySha: DISCOVERY.repositorySha,
  });
  await postNext(relay, {
    relayUrl: RELAY_URL, sessionId: SESSION_ID, role: "payer", kind: "mandate",
    body: {
      common: mandate.common,
      expiresAtMs: String(mandate.expiresAtMs),
      issuedAtMs: String(mandate.issuedAtMs),
      mandateEnvelope: mandate.mandateEnvelope,
      sessionUuid: mandate.sessionUuid,
      paymentMoved: false,
    },
    keyPair: kp,
  });
  say("TERMS_PUBLISHED", "Signed payment terms published. Waiting for the requestor to submit its request.");

  const handshake = await awaitKind("handshake_required", WAIT_MS);
  const { descriptorEnvelope, repositoryPublicKey } = handshake.body;
  try {
    assertHandshakeRepositoryKey({ discovery: DISCOVERY, handshake });
  } catch (error) {
    stop("MALFORMED", error.message);
  }
  say("PROPOSED", "Received the signed terms. Checking them and opening the authorization window.");

  await awaitKind("watching", WAIT_MS);
  say("REQUEST_SUBMITTED", "The requestor is watching the ledger. Opening the window now.");

  const root = await mkdtemp(join(tmpdir(), "handshake-payer-"));
  const directory = join(root, "payer");
  await mkdir(directory, { mode: 0o700, recursive: true });
  await chmod(directory, 0o700);

  const payerResult = await runPayerRole({
    client: clockchain,
    descriptorEnvelope,
    outputDirectory: directory,
    ownerOf: ({ agentId: id, registry }) =>
      publicClient.readContract({ abi: ERC8004_ABI, address: registry, args: [BigInt(id)], functionName: "ownerOf" }),
    repositoryPublicKey,
    signMessage: (bytes) => account.signMessage({ message: { raw: bytes } }),
  });

  try {
    await postNext(relay, {
      relayUrl: RELAY_URL,
      sessionId: SESSION_ID,
      role: "payer",
      kind: "anchor_report",
      body: { anchors: anchorReportFrom(payerResult.transitions), paymentMoved: false },
      keyPair: kp,
    });
  } catch {
    // The board can lag; the evidence and certificate path decides the run.
  }

  const [json, markdown, marker] = await Promise.all([
    readFile(join(directory, "party-result.json"), "utf8"),
    readFile(join(directory, "PARTY-RESULT.md"), "utf8"),
    readFile(join(directory, ".party-result.complete.json"), "utf8"),
  ]);
  await relay.putEvidence({
    relayUrl: RELAY_URL, sessionId: SESSION_ID, role: "payer",
    json, markdown, marker,
  });
  say("ACKNOWLEDGED", "Our side is recorded on Clockchain and our evidence is delivered.");

  let certificate = null;
  const certificateDeadline = Date.now() + 5 * 60_000;
  while (Date.now() < certificateDeadline) {
    let envelope = null;
    try {
      envelope = await relay.getResult({ relayUrl: RELAY_URL, sessionId: SESSION_ID });
    } catch {
      // Not published yet (RESULT_NOT_SET) or a transient relay error: both
      // are "keep waiting" inside the bounded window, not failures.
    }
    if (envelope !== null) {
      try {
        verifyResultEnvelope(envelope, { expectedPublicKey: DISCOVERY.operatorPublicKey });
        certificate = envelope;
      } catch (error) {
        say("VERIFYING", `A closing certificate arrived but did NOT verify against this session's operator key (${error?.message ?? "unknown"}). Refusing it.`);
      }
      break;
    }
    say("VERIFYING", "Waiting for the independent verifier's signed certificate.");
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }

  if (certificate !== null) {
    await writeFile(join(directory, "closing-certificate.json"), JSON.stringify(certificate, null, 2));
    const r = certificate.result;
    process.stdout.write(
      `\nThe independent verifier's certificate has arrived, and its signature\n` +
      `verifies against this session's operator key.\n\n` +
      `  ${r.outcome}\n` +
      `  No money moved: ${r.paymentMoved === false}\n` +
      r.anchors.map((a) => `  ${a.kind}  block ${a.blockHeight}  ledger ${a.ledgerId}`).join("\n") +
      `\n\nSaved to: ${join(directory, "closing-certificate.json")}\n` +
      `That result is the checker's signed word, not ours. No money has moved.\n` +
      `\nEvidence: ${directory}\n`,
    );
  } else {
    process.stdout.write(
      "\nOur side is complete — and that is NOT authorization.\n" +
      "The verifier's certificate did not arrive within the wait window, so this kit has no closing word.\n" +
      "No money has moved at any point.\n" +
      `\nEvidence: ${directory}\n`,
    );
  }
}

main().catch((error) => {
  if (process.env.HANDSHAKE_DEBUG) process.stderr.write(`${error?.stack}\n`);
  stop(error?.terminalCode ?? error?.code ?? "FAILED", error?.message ?? "The run stopped.");
});
