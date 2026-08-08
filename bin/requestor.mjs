#!/usr/bin/env node
/**
 * The Requestor kit — the only thing a stakeholder runs.
 *
 * It receives ONE URL and nothing else: no key, no token, no session id to copy by
 * hand. It fetches the invitation behind that URL, checks it, generates its own
 * keypair, asks to be paid, follows whatever the payer's response tells it to do,
 * registers its own on-chain identity, and records its acceptance. It never claims
 * the run succeeded — only the operator's independent verifier can say that, and
 * this says so out loud.
 */
import { chmod, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createPublicClient, createWalletClient, http } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";

import * as relay from "../src/relay/client.mjs";
import { buildRequest, fetchDiscovery, postNext, roleAlreadySeated, say, stop } from "../src/roles/session.mjs";
import { verifyResultEnvelope } from "../src/core/result.mjs";
import { createMcpClient, mintDemoToken } from "../src/core/clockchain.mjs";
import { ERC8004_ABI } from "../src/core/registration.mjs";
import { runPayeeRole } from "../src/core/roles-core.mjs";
import { REGISTRY_ADDRESS, RPC_URL } from "../src/core/constants.mjs";
import { selectFundingRecord } from "../src/roles/funding-selection.mjs";

const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i], process.argv[i + 1]);
const DISCOVERY_URL = args.get("--discovery-url") ?? process.env.HANDSHAKE_DISCOVERY ?? null;
// Resolved either from the invitation (the stakeholder path) or from the explicit
// pair (our own testing escape hatch). Nothing downstream cares which.
let RELAY_URL = args.get("--relay-url") ?? process.env.HANDSHAKE_RELAY ?? null;
let SESSION_ID = args.get("--session") ?? process.env.HANDSHAKE_SESSION ?? null;

/**
 * Turn the one thing a stakeholder was given into somewhere to dial out to.
 *
 * The relay is an untrusted mailbox, so the invitation it serves is checked before
 * a single byte of it is used. This runs before any anchor exists, which makes it
 * the one moment a refusal costs nothing.
 */
async function resolveRendezvous() {
  if (RELAY_URL && SESSION_ID) return;
  if (!DISCOVERY_URL) {
    stop("MALFORMED", "This needs one thing: --discovery-url followed by the link the payer sent you.");
  }
  say("SESSION_STARTED", "Opening the payer's link.");
  const found = await fetchDiscovery({
    discoveryUrl: DISCOVERY_URL,
    onHeartbeat: () => say("SESSION_STARTED", "Still trying the payer's link. No money has moved."),
  });
  if (!found.ok) stop(found.reason, found.sentence);
  RELAY_URL = found.discovery.relayUrl;
  SESSION_ID = found.discovery.sessionId;
  say("SESSION_STARTED", "The link checks out. Joining the payer's session.", {
    sessionId: SESSION_ID,
  });
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
    const selected = selectFundingRecord(got.messages, { address, role: "requestor" });
    if (selected.status === "proceed") return selected.message;
    if (selected.status === "already-bound") {
      stop("ROLE_ALREADY_BOUND",
        "The payer funded a different requestor: another agent claimed this session first. Nothing was spent.");
    }
    if (Date.now() - lastBeat > HEARTBEAT_MS) {
      lastBeat = Date.now();
      say("REQUEST_SUBMITTED", "Still working — waiting on the payer. No money has moved.");
    }
  }
  stop("EXPIRED", "The payer did not respond before the session window closed.");
}

async function main() {
  await resolveRendezvous();
  say("SESSION_STARTED", "Asking to be paid. This is a verification exercise: no money will move.");

  // One requestor per session. The relay is an untrusted mailbox and
  // deliberately does not adjudicate who holds a role, so the check belongs
  // here: look before claiming, and stop plainly if the seat is taken. Without
  // it a second agent joined silently, waited for a funding record addressed to
  // somebody else, and then failed on an opaque out-of-gas error.
  const seated = await relay.pollMessages({
    relayUrl: RELAY_URL, sessionId: SESSION_ID, after: "0", waitMs: 0,
  });
  if (roleAlreadySeated(seated.messages, "requestor")) {
    stop("ROLE_ALREADY_BOUND",
      "Another requestor already joined this session. Only one can be paid per session — ask the payer to open a fresh one.");
  }

  // Our own key, generated here. The operator never sees it and cannot produce it.
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  const kp = relay.generateEnvelopeKeyPair();
  say("REQUEST_SUBMITTED", "Generated a fresh identity key for this run.", { address: account.address });

  await postNext(relay, { relayUrl: RELAY_URL, sessionId: SESSION_ID, role: "requestor", kind: "identity_ready", body: { address: account.address.toLowerCase(), paymentMoved: false }, keyPair: kp });
  say("HANDSHAKE_REQUIRED",
    "The payer will not consider a payment without a verified handshake first. Following its instructions.");

  const funding = await awaitFundingRecord(account.address, WAIT_MS);
  // The record names the address the payer actually funded. Two requestors can
  // still both pass the check above if they claim in the same instant, and the
  // payer serves whichever arrived first -- so this is where that race is
  // caught. Ours is the only address we can register from; if the payer funded
  // someone else, registering would spend gas we do not have.
  if (String(funding.body?.funded ?? "").toLowerCase() !== account.address.toLowerCase()) {
    stop("ROLE_ALREADY_BOUND",
      "The payer funded a different requestor: another agent claimed this session first. Nothing was spent.");
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

  await postNext(relay, { relayUrl: RELAY_URL, sessionId: SESSION_ID, role: "requestor", kind: "party_ready", body: { address: account.address.toLowerCase(), agentId, paymentMoved: false }, keyPair: kp });

  const terms = await awaitKind("mandate", WAIT_MS);
  say("HANDSHAKE_REQUIRED", "Received the payer's signed terms. Submitting a payment request against them.");
  const requestEnvelope = await buildRequest({
    common: terms.body.common,
    expiresAtMs: Number(terms.body.expiresAtMs),
    issuedAtMs: Number(terms.body.issuedAtMs),
    mandateEnvelope: terms.body.mandateEnvelope,
    requestorAccount: account,
  });
  await postNext(relay, {
    relayUrl: RELAY_URL, sessionId: SESSION_ID, role: "requestor", kind: "payment_request",
    body: { requestEnvelope, paymentMoved: false }, keyPair: kp,
  });
  say("REQUEST_SUBMITTED", "Our signed payment request is submitted. Waiting for the payer to open the window.");

  const handshake = await awaitKind("handshake_required", WAIT_MS);
  const { descriptorEnvelope, repositoryPublicKey } = handshake.body;
  say("PROPOSED", "Received the signed terms. Checking them and recording our acceptance.");

  const root = await mkdtemp(join(tmpdir(), "handshake-req-"));
  const directory = join(root, "payee");
  await mkdir(directory, { mode: 0o700, recursive: true });
  await chmod(directory, 0o700);

  await postNext(relay, {
    relayUrl: RELAY_URL, sessionId: SESSION_ID, role: "requestor", kind: "watching",
    body: { paymentMoved: false }, keyPair: kp,
  });
  say("PROPOSED", "Watching the ledger for the payer's proposal.");

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

  const [json, markdown, marker] = await Promise.all([
    readFile(join(directory, "party-result.json"), "utf8"),
    readFile(join(directory, "PARTY-RESULT.md"), "utf8"),
    readFile(join(directory, ".party-result.complete.json"), "utf8"),
  ]);
  await relay.putEvidence({
    relayUrl: RELAY_URL, sessionId: SESSION_ID, role: "payee",
    json, markdown, marker,
  });
  say("ACCEPTED", "Our acceptance is recorded on Clockchain and our evidence is delivered.");

  // The closing certificate. Until now this side finished blind: the verdict
  // appeared on the payer's screen and never here. The verifier's signed
  // certificate is fetched from the session and checked against the operator
  // key this run's descriptor named -- the same key that gated every earlier
  // step -- so what gets read back is the checker's own signed word, not this
  // side's claim about itself.
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
        verifyResultEnvelope(envelope, { expectedPublicKey: repositoryPublicKey });
        certificate = envelope;
      } catch (error) {
        // Fail closed on the artifact, honestly: a document that does not
        // verify against this session's operator key is treated as absent,
        // and saying so beats pretending it never arrived.
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
      `  Its verdict: ${r.outcome}\n` +
      `  No money moved: ${r.paymentMoved === false}\n` +
      r.anchors.map((a) => `  ${a.kind}  block ${a.blockHeight}  ledger ${a.ledgerId}`).join("\n") +
      `\n\nSaved to: ${join(directory, "closing-certificate.json")}\n` +
      `That verdict is the checker's signed word, not ours. No money has moved.\n` +
      `\nEvidence: ${directory}\n`,
    );
  } else {
    process.stdout.write(
      "\nOur side is complete — and that is NOT authorization.\n" +
      "The verifier's certificate did not arrive within the wait window, so the\n" +
      "outcome was decided on the payer's side. No money has moved at any point.\n" +
      `\nEvidence: ${directory}\n`,
    );
  }
}

main().catch((error) => {
  if (process.env.HANDSHAKE_DEBUG) process.stderr.write(`${error?.stack}\n`);
  stop(error?.terminalCode ?? error?.code ?? "FAILED", error?.message ?? "The run stopped.");
});
