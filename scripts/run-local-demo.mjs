#!/usr/bin/env node
/**
 * The local end-to-end run: two role processes complete the bilateral handshake
 * against the REAL Clockchain and the REAL Sepolia registry, then a fresh
 * verifier re-checks everything from scratch.
 *
 * Sequencing matters more than anything else here. Everything human-paced —
 * funding, on-chain registration, both parties reporting ready — happens BEFORE
 * a single anchor exists, so nothing can expire while we wait. Only once both
 * sides are ready does the payer anchor PROPOSED, opening the 600-second window
 * that contains just two machine-paced Clockchain writes.
 *
 * No money moves. The four funded addresses pay gas for identity registration
 * and nothing else; paymentMoved:false rides on every artifact.
 */
import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { chmod, mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createPublicClient, createWalletClient, http, parseEther } from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { sepolia } from "viem/chains";

import { createMcpClient, mintDemoToken } from "../src/core/clockchain.mjs";
import { createSignedEnvelope, dSession } from "../src/core/descriptor.mjs";
import { payerMandateDigest, signPayerMandate } from "../src/core/payer-mandate.mjs";
import { paymentRequestDigest, signPaymentRequest } from "../src/core/payment-request.mjs";
import { runPayerRole, runPayeeRole } from "../src/core/roles-core.mjs";
import { verifyBilateralAuthorization } from "../src/core/verdict.mjs";
import { openFundingWallet } from "../src/core/funding/wallet.mjs";
import { ERC8004_ABI } from "../src/core/registration.mjs";
import { CHAIN_ID, REGISTRY_ADDRESS, RPC_URL } from "../src/core/constants.mjs";

const KEYSTORE = process.env.HANDSHAKE_KEYSTORE ?? join(process.cwd(), "keys/funding-wallet.json");
const FUND_AMOUNT = parseEther("0.01");
const REPO_SHA = process.env.HANDSHAKE_SHA ?? "0".repeat(40);
const STUB = process.argv.includes("--stub");

// Business-language progress. Every line carries paymentMoved:false because a
// live audience is reading this and that fact is the point.
function say(stage, sentence, extra = {}) {
  const line = { stage, message: sentence, paymentMoved: false, ...extra };
  process.stdout.write(`${sentence}\n`);
  process.stderr.write(`${JSON.stringify(line)}\n`);
}

function fail(reason, sentence) {
  process.stdout.write(`\nStopped: ${sentence}\n`);
  process.stderr.write(`${JSON.stringify({ reason, paymentMoved: false })}\n`);
  process.exit(1);
}

const publicClient = createPublicClient({ chain: sepolia, transport: http(RPC_URL) });

async function fundAndRegister(treasuryAccount, label) {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  if (STUB) {
    // Deterministic id per party; no chain traffic, no gas.
    const agentId = String(8600 + (label === "payer" ? 77 : 78));
    say("IDENTITY_REGISTERED", `The ${label} holds identity #${agentId} (stub mode: no chain writes).`, {
      address: account.address, agentId,
    });
    return { account, agentId, privateKey };
  }
  const wallet = createWalletClient({ account: treasuryAccount, chain: sepolia, transport: http(RPC_URL) });

  say("FUNDED", `Preparing a fresh ${label} identity and covering its registration gas.`, {
    address: account.address,
  });
  const fundTx = await wallet.sendTransaction({ to: account.address, value: FUND_AMOUNT });
  await publicClient.waitForTransactionReceipt({ hash: fundTx, timeout: 180_000 });

  const own = createWalletClient({ account, chain: sepolia, transport: http(RPC_URL) });
  const registerTx = await own.writeContract({
    abi: ERC8004_ABI,
    address: REGISTRY_ADDRESS,
    functionName: "register",
    args: [`https://clockchain-research.vercel.app/handshake/agent/${account.address}`],
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash: registerTx, timeout: 180_000 });

  // The agent id is the ERC-721 token id the registry mints. Take it from the
  // Transfer log whose `from` is the zero address — that is the mint, and its
  // fourth topic is the token id. Matching on "last topic of any registry log"
  // silently returns the same value for every registration.
  const ZERO = `0x${"0".repeat(64)}`;
  let agentId = null;
  for (const log of receipt.logs) {
    if (log.address.toLowerCase() !== REGISTRY_ADDRESS.toLowerCase()) continue;
    if (log.topics.length !== 4 || log.topics[1] !== ZERO) continue;
    agentId = BigInt(log.topics[3]).toString();
  }
  if (!agentId) fail("FAILED", `Could not read the ${label} identity id from the registry.`);

  say("IDENTITY_REGISTERED", `The ${label} now holds a fresh on-chain identity (#${agentId}).`, {
    address: account.address,
    agentId,
  });
  return { account, agentId, privateKey };
}

async function main() {
  say("SESSION_STARTED", "Starting a payment-authorization handshake. No money will move at any point.");

  const treasury = STUB
    ? { account: null, metadata: { fundingAddress: "0x" + "00".repeat(20) } }
    : await openFundingWallet({ keystorePath: KEYSTORE });
  say("SESSION_STARTED", "Operator treasury is available to cover testnet gas.", {
    treasury: treasury.metadata.fundingAddress,
  });

  const payer = await fundAndRegister(treasury.account, "payer");
  const requestor = await fundAndRegister(treasury.account, "requestor");

  // The operator signs the session descriptor. Its key is the only thing a
  // requestor needs to trust; everything else is checked against it.
  const { privateKey: opPriv, publicKey: opPub } = generateKeyPairSync("ed25519");
  const operatorPrivateKeyPem = opPriv.export({ format: "pem", type: "pkcs8" });
  const repositoryPublicKey = opPub
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");

  // The mandate and the payment request are the commercial-intent evidence. Their
  // digests are bound INTO the signed descriptor, so they must be built first —
  // the verifier recomputes both and refuses any mismatch.
  const sessionUuid = randomUUID();
  const intakeRequestId = randomUUID();
  const issuedAtMs = Date.now();
  const expiresAtMs = issuedAtMs + 45 * 60_000;   // >= 30 min: published before a human-paced wait
  const amount = { currency: "USD", value: "100" };
  const intakeDigest = createHash("sha256").update(intakeRequestId).digest("hex");

  const mandateEnvelope = await signPayerMandate({
    mandate: {
      amount,
      expiresAtMs: String(expiresAtMs),
      intakeDigest,
      intakeRequestId,
      invoiceReferencePrefix: "INV-",
      issuedAtMs: String(issuedAtMs),
      payee: { address: requestor.account.address.toLowerCase(), agentId: requestor.agentId },
      payer: { address: payer.account.address.toLowerCase(), agentId: payer.agentId },
      paymentMoved: false,
      protocol: "clockchain.bilateral-authorization/v1",
      purpose: "Invoice settlement",
      releaseId: "handshake-v6",
      repositorySha: REPO_SHA,
      requestEndpoint: `/v1/sessions/${sessionUuid}/payment-requests`,
      schema: "clockchain.bilateral-payer-mandate/v1",
      sessionId: sessionUuid,
      subjectRun: "stakeholder",
    },
    signMessage: (bytes) => payer.account.signMessage({ message: { raw: bytes } }),
  });

  const requestEnvelope = await signPaymentRequest({
    request: {
      amount,
      createdAtMs: String(issuedAtMs + 1000),
      expiresAtMs: String(expiresAtMs),
      intakeDigest,
      intakeRequestId,
      invoiceReference: "INV-0001",
      mandateDigest: payerMandateDigest(mandateEnvelope),
      payee: { address: requestor.account.address.toLowerCase(), agentId: requestor.agentId },
      payer: { address: payer.account.address.toLowerCase(), agentId: payer.agentId },
      paymentMoved: false,
      protocol: "clockchain.bilateral-authorization/v1",
      purpose: "Invoice settlement",
      releaseId: "handshake-v6",
      repositorySha: REPO_SHA,
      requestId: randomUUID(),
      schema: "clockchain.bilateral-payment-request/v1",
      sessionId: sessionUuid,
      subjectRun: "stakeholder",
    },
    signMessage: (bytes) => requestor.account.signMessage({ message: { raw: bytes } }),
  });

  const descriptor = {
    amountOptions: [amount],
    chainId: String(CHAIN_ID),
    expirySeconds: "600",
    mandateDigest: payerMandateDigest(mandateEnvelope),
    namespace: "cbv1",
    payee: { address: requestor.account.address.toLowerCase(), agentId: requestor.agentId, displayName: "Requestor", role: "payee" },
    payer: { address: payer.account.address.toLowerCase(), agentId: payer.agentId, displayName: "Payer", role: "payer" },
    paymentMoved: false,
    promptSha256: createHash("sha256").update("prompt").digest("hex"),
    protocol: "clockchain.bilateral-authorization/v1",
    protocolVersion: "1",
    registry: REGISTRY_ADDRESS.toLowerCase(),
    repositorySha: REPO_SHA,
    requestDigest: paymentRequestDigest(requestEnvelope),
    schema: "clockchain.bilateral-session-descriptor/v2",
    // 32 lowercase hex, not a dashed uuid — the canonical profile is strict here.
    sessionId: sessionUuid.replace(/-/g, ""),
    settlement: "not-executed",
  };
  const envelope = createSignedEnvelope(descriptor, {
    keyId: "bilateral-demo-2026-07-28",
    privateKeyPem: operatorPrivateKeyPem,
  });
  say("TERMS_PUBLISHED", "The payer published signed payment terms and the session is open.", {
    sessionDigest: dSession(descriptor),
  });

  let makeClient;
  let stubClock = 0;
  if (STUB) {
    const { createFakeBilateralClockchain } = await import(
      "../test/helpers/fake-bilateral-clockchain.mjs"
    );
    const fake = createFakeBilateralClockchain();
    fake.registerAgent({ agentId: payer.agentId, owner: payer.account.address, status: "active" });
    fake.registerAgent({ agentId: requestor.agentId, owner: requestor.account.address, status: "active" });
    makeClient = () => fake;
    stubClock = fake.baseTimeMs ?? 1_784_923_100_000;
  }
  // Token minting is rate-limited, and a demo that cannot be rehearsed is not a
  // demo. Cache the minted token in the operator-local (git-ignored) keys dir and
  // reuse it until it stops working.
  const tokenPath = join(process.cwd(), "keys/clockchain.token");
  let token = "stub";
  if (!STUB) {
  try {
    token = (await readFile(tokenPath, "utf8")).trim();
    if (!token) throw new Error("empty");
  } catch {
    token = await mintDemoToken({});
    await writeFile(tokenPath, token, { mode: 0o600 });
  }
  }
  if (!STUB) makeClient = () => createMcpClient({ token });
  const ownerOf = STUB
    ? async ({ agentId }) =>
        agentId === payer.agentId ? payer.account.address : requestor.account.address
    : ({ agentId, registry }) =>
        publicClient.readContract({ abi: ERC8004_ABI, address: registry, args: [BigInt(agentId)], functionName: "ownerOf" });

  const root = await mkdtemp(join(tmpdir(), "handshake-run-"));
  const payerDirectory = join(root, "payer");
  const payeeDirectory = join(root, "payee");
  await mkdir(payerDirectory, { mode: 0o700, recursive: true });
  await mkdir(payeeDirectory, { mode: 0o700, recursive: true });
  await chmod(payerDirectory, 0o700);
  await chmod(payeeDirectory, 0o700);

  say("REQUEST_SUBMITTED", "Both sides are funded, registered and ready. Opening the authorization window.");

  // Both roles run concurrently: the payer anchors PROPOSED and watches for the
  // requestor's ACCEPTED, the requestor watches for PROPOSED and answers it.
  const clockOpts = STUB ? { now: () => stubClock } : {};
  const [payerResult, payeeResult] = await Promise.all([
    runPayerRole({
      ...clockOpts,
      client: makeClient(),
      descriptorEnvelope: envelope,
      outputDirectory: payerDirectory,
      ownerOf,
      repositoryPublicKey,
      signMessage: (bytes) => payer.account.signMessage({ message: { raw: bytes } }),
    }),
    runPayeeRole({
      ...clockOpts,
      client: makeClient(),
      descriptorEnvelope: envelope,
      outputDirectory: payeeDirectory,
      ownerOf,
      repositoryPublicKey,
      signMessage: (bytes) => requestor.account.signMessage({ message: { raw: bytes } }),
    }),
  ]);

  say("ACKNOWLEDGED", "All three steps are recorded on Clockchain in order.", {
    payer: payerResult?.state ?? "complete",
    requestor: payeeResult?.state ?? "complete",
  });

  say("VERIFYING", "An independent verifier is now re-checking every piece of evidence from scratch.");
  const verdict = await verifyBilateralAuthorization({
    clockchain: makeClient(),
    descriptorEnvelope: envelope,
    mandateEnvelope,
    ownerOf,
    payerDirectory,
    payeeDirectory,
    requestEnvelope,
    repositoryPublicKeyResolver: async () => repositoryPublicKey,
  });

  process.stdout.write(`\nVerifier outcome: ${verdict.outcome}\n`);
  process.stdout.write(`No money moved: ${verdict.paymentMoved === false}\n`);
  for (const t of verdict.transitions ?? []) {
    process.stdout.write(`  ${t.kind}  block ${t.blockHeight}  ledger ${t.ledgerId}\n`);
  }
}

main().catch((error) => {
  if (process.env.HANDSHAKE_DEBUG) {
    process.stderr.write(`DEBUG ${error?.name} code=${error?.terminalCode ?? error?.code} : ${error?.message}\n${error?.stack ?? ""}\n`);
    if (error?.cause) process.stderr.write(`CAUSE: ${error.cause?.name}: ${error.cause?.message}\n${error.cause?.stack ?? ""}\n`);
  }
  fail(error?.terminalCode ?? error?.code ?? "FAILED", error?.message ?? "The run stopped.");
});
