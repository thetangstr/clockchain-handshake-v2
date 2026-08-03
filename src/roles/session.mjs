/**
 * Shared session construction for the operator and the requestor kit.
 *
 * The split matters: the operator owns the treasury and the signing key, the
 * requestor owns nothing but a keypair it generates on its own machine. The only
 * thing that crosses between them is the signed discovery document and, later,
 * the signed session descriptor — both published through the relay, which
 * validates neither. Authority lives in the signatures and the Clockchain
 * receipts, so an untrusted mailbox in the middle is fine by construction.
 */
import { createHash, randomUUID } from "node:crypto";

import { payerMandateDigest, signPayerMandate } from "../core/payer-mandate.mjs";
import { paymentRequestDigest, signPaymentRequest } from "../core/payment-request.mjs";
import { CHAIN_ID, REGISTRY_ADDRESS } from "../core/constants.mjs";

export const DISCOVERY_SCHEMA = "handshake-discovery/v2";

/** Human-readable progress. paymentMoved rides on every line: it is the point. */
export function say(stage, sentence, extra = {}) {
  process.stdout.write(`${sentence}\n`);
  process.stderr.write(
    `${JSON.stringify({ stage, message: sentence, paymentMoved: false, ...extra })}\n`,
  );
}

export function stop(reason, sentence) {
  process.stdout.write(`\nStopped: ${sentence}\n`);
  process.stderr.write(`${JSON.stringify({ reason, paymentMoved: false })}\n`);
  process.exit(1);
}

/**
 * Build the commercial-intent evidence and the session descriptor.
 *
 * Order is forced by the digests: the mandate and the request must exist before
 * the descriptor, because their digests are bound into it and the verifier
 * recomputes both from scratch. Getting this backwards produces a descriptor that
 * validates locally and fails at the verifier, which is the worst place to learn.
 */
export async function buildSession({
  payerAccount,
  payerAgentId,
  requestorAccount,
  requestorAgentId,
  repositorySha,
  subjectRun = "stakeholder",
}) {
  const sessionUuid = randomUUID();
  const intakeRequestId = randomUUID();
  const issuedAtMs = Date.now();
  // >= 30 minutes: the terms are published before a human-paced wait, so a tight
  // expiry would lapse while the payer is still legitimately waiting.
  const expiresAtMs = issuedAtMs + 45 * 60_000;
  const amount = { currency: "USD", value: "100" };
  const intakeDigest = createHash("sha256").update(intakeRequestId).digest("hex");

  const parties = {
    payee: { address: requestorAccount.address.toLowerCase(), agentId: requestorAgentId },
    payer: { address: payerAccount.address.toLowerCase(), agentId: payerAgentId },
  };
  const common = {
    amount,
    intakeDigest,
    intakeRequestId,
    ...parties,
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    purpose: "Invoice settlement",
    releaseId: "handshake-v6",
    repositorySha,
    sessionId: sessionUuid,
    subjectRun,
  };

  const mandateEnvelope = await signPayerMandate({
    mandate: {
      ...common,
      expiresAtMs: String(expiresAtMs),
      invoiceReferencePrefix: "INV-",
      issuedAtMs: String(issuedAtMs),
      requestEndpoint: `/v1/sessions/${sessionUuid}/payment-requests`,
      schema: "clockchain.bilateral-payer-mandate/v1",
    },
    signMessage: (bytes) => payerAccount.signMessage({ message: { raw: bytes } }),
  });

  const requestEnvelope = await signPaymentRequest({
    request: {
      ...common,
      createdAtMs: String(issuedAtMs + 1000),
      expiresAtMs: String(expiresAtMs),
      invoiceReference: "INV-0001",
      mandateDigest: payerMandateDigest(mandateEnvelope),
      requestId: randomUUID(),
      schema: "clockchain.bilateral-payment-request/v1",
    },
    signMessage: (bytes) => requestorAccount.signMessage({ message: { raw: bytes } }),
  });

  const descriptor = {
    amountOptions: [amount],
    chainId: String(CHAIN_ID),
    expirySeconds: "600",
    mandateDigest: payerMandateDigest(mandateEnvelope),
    namespace: "cbv1",
    payee: { ...parties.payee, displayName: "Requestor", role: "payee" },
    payer: { ...parties.payer, displayName: "Payer", role: "payer" },
    paymentMoved: false,
    promptSha256: createHash("sha256").update("requestor-prompt").digest("hex"),
    protocol: "clockchain.bilateral-authorization/v1",
    protocolVersion: "1",
    registry: REGISTRY_ADDRESS.toLowerCase(),
    repositorySha,
    requestDigest: paymentRequestDigest(requestEnvelope),
    schema: "clockchain.bilateral-session-descriptor/v2",
    sessionId: sessionUuid.replace(/-/g, ""),
    settlement: "not-executed",
  };

  return { descriptor, mandateEnvelope, requestEnvelope, sessionUuid };
}

/** The five audience-facing steps. Internal codes never reach a viewer. */
export const BUSINESS_STAGE = Object.freeze({
  ACCEPTED: "The requestor accepted the exact terms, and that acceptance is recorded.",
  ACKNOWLEDGED: "The payer acknowledged. All three steps are now on the ledger.",
  FUNDED: "The operator covered testnet gas so identities can be registered.",
  HANDSHAKE_REQUIRED:
    "The payer will not consider a payment without a verified handshake first.",
  IDENTITY_REGISTERED: "A fresh on-chain identity was registered for this run.",
  PROPOSED: "The payer published the payment terms and recorded them.",
  REQUEST_SUBMITTED: "The requestor asked to be paid.",
  SESSION_STARTED: "A new authorization session is open. No money will move.",
  TERMS_PUBLISHED: "The signed terms are published and the session is open.",
  VERIFYING: "An independent verifier is re-checking every piece of evidence.",
});
