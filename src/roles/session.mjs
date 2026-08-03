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

/**
 * The discovery document is the entire handover. A stakeholder receives one URL
 * and nothing else — no key, no token, no session id to copy by hand — so this
 * document has to carry everything the kit needs and has to be checked before any
 * of it is believed. A relay is an untrusted mailbox; it will serve whatever it
 * was given.
 */
const DISCOVERY_REQUIRED = Object.freeze([
  "schema", "sessionId", "relayUrl", "kitRepoUrl", "repositorySha",
  "operatorPublicKey", "issuedAtMs", "expiresAtMs", "paymentMoved",
]);

// A person has to read a prompt, clone a repo and npm ci before they can appear.
// An invitation whose whole life is shorter than that is malformed by definition,
// not merely unlucky — so refuse it up front rather than expiring mid-run.
const DISCOVERY_MIN_LIFETIME_MS = 30 * 60_000;

const SESSION_ID_SHAPE = /^[A-Za-z0-9_-]{1,128}$/;

function malformed(sentence) {
  return { ok: false, reason: "MALFORMED", sentence };
}

function wholeMs(value) {
  if (typeof value !== "string" && typeof value !== "number") return null;
  if (typeof value === "string" && !/^[0-9]{1,15}$/.test(value)) return null;
  const millis = Number(value);
  return Number.isSafeInteger(millis) && millis > 0 ? millis : null;
}

/** An origin we are willing to dial out to, with no query or fragment smuggled in. */
function normalizeHttpUrl(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) return null;
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.search !== "" || url.hash !== "") return null;
  return `${url.origin}${url.pathname}`.replace(/\/+$/, "");
}

/** The single line an operator hands over. Everything else is derived from it. */
export function discoveryUrlFor({ relayUrl, sessionId }) {
  const base = String(relayUrl).replace(/\/+$/, "");
  return `${base}/v1/discovery/${encodeURIComponent(sessionId)}`;
}

/**
 * Validate a discovery document and return the fields the kit will act on.
 *
 * Returns a result rather than throwing, so the caller decides how to close: this
 * runs before any anchor exists, which is the one moment a clean public refusal is
 * still free.
 */
export function readDiscovery(document, { now = Date.now() } = {}) {
  if (document === null || typeof document !== "object" || Array.isArray(document)) {
    return malformed("That link did not return an invitation.");
  }
  if (document.schema !== DISCOVERY_SCHEMA) {
    return malformed("That link is not an invitation this kit knows how to read.");
  }
  for (const key of DISCOVERY_REQUIRED) {
    if (document[key] === undefined || document[key] === null) {
      return malformed(`The invitation is incomplete: it has no ${key}.`);
    }
  }
  if (document.paymentMoved !== false) {
    return malformed("The invitation does not carry the guarantee that no money moves.");
  }
  if (typeof document.sessionId !== "string" || !SESSION_ID_SHAPE.test(document.sessionId)) {
    return malformed("The invitation names a session we cannot address.");
  }
  const relayUrl = normalizeHttpUrl(document.relayUrl);
  if (relayUrl === null) {
    return malformed("The invitation gives no usable address to dial out to.");
  }
  if (normalizeHttpUrl(document.kitRepoUrl) === null) {
    return malformed("The invitation gives no usable address for the kit itself.");
  }
  if (typeof document.repositorySha !== "string" || !/^[0-9a-f]{40}$/.test(document.repositorySha)) {
    return malformed("The invitation does not pin a readable version of the kit.");
  }
  if (
    typeof document.operatorPublicKey !== "string" ||
    document.operatorPublicKey.length === 0 ||
    document.operatorPublicKey.length > 512
  ) {
    return malformed("The invitation carries no usable payer key.");
  }
  const issuedAtMs = wholeMs(document.issuedAtMs);
  const expiresAtMs = wholeMs(document.expiresAtMs);
  if (issuedAtMs === null || expiresAtMs === null) {
    return malformed("The invitation is not dated in a way we can check.");
  }
  if (expiresAtMs - issuedAtMs < DISCOVERY_MIN_LIFETIME_MS) {
    return malformed("The invitation's window is too short for a person to act inside.");
  }
  if (now >= expiresAtMs) {
    return {
      ok: false,
      reason: "EXPIRED",
      sentence: "That invitation has already expired. Ask the payer for a fresh link.",
    };
  }
  return {
    ok: true,
    discovery: { ...document, expiresAtMs, issuedAtMs, relayUrl, sessionId: document.sessionId },
  };
}

/**
 * Fetch and validate the discovery document behind one URL.
 *
 * Retries, because the operator publishes and reads the link out in the same
 * breath and a person pasting it may well arrive first. This is not a human-paced
 * wait — nobody has to act during it — so a short machine-paced budget is correct.
 */
export async function fetchDiscovery({
  discoveryUrl,
  budgetMs = 120_000,
  fetchImpl = globalThis.fetch,
  now = Date.now,
  onHeartbeat = () => {},
  requestBudgetMs = 15_000,
  retryPauseMs = 5_000,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
  if (normalizeHttpUrl(discoveryUrl) === null) {
    return malformed("That does not look like a link. Paste the whole thing the payer sent.");
  }
  const deadline = now() + budgetMs;
  let attempt = 0;
  for (;;) {
    let response = null;
    try {
      response = await fetchImpl(discoveryUrl, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(requestBudgetMs),
      });
    } catch {
      response = null;
    }
    if (response?.ok) {
      let document;
      try {
        document = await response.json();
      } catch {
        return malformed("That link answered, but not with a readable invitation.");
      }
      return readDiscovery(document, { now: now() });
    }
    if (now() >= deadline) {
      return {
        ok: false,
        reason: "RENDEZVOUS_UNAVAILABLE",
        sentence: "The payer's link is not answering. Check the link, or ask for a fresh one.",
      };
    }
    attempt += 1;
    onHeartbeat(attempt);
    await sleep(retryPauseMs);
  }
}

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
export async function buildMandate({
  payerAccount,
  payerAgentId,
  requestorAddress,
  requestorAgentId,
  repositorySha,
  subjectRun = "stakeholder",
}) {
  const sessionUuid = randomUUID();
  const intakeRequestId = randomUUID();
  const issuedAtMs = Date.now();
  const expiresAtMs = issuedAtMs + 45 * 60_000;
  const amount = { currency: "USD", value: "100" };
  const intakeDigest = createHash("sha256").update(intakeRequestId).digest("hex");
  const common = {
    amount,
    intakeDigest,
    intakeRequestId,
    payee: { address: requestorAddress.toLowerCase(), agentId: requestorAgentId },
    payer: { address: payerAccount.address.toLowerCase(), agentId: payerAgentId },
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
  return { common, expiresAtMs, issuedAtMs, mandateEnvelope, sessionUuid };
}

/** The requestor signs its own payment request; only it holds that key. */
export async function buildRequest({ common, expiresAtMs, issuedAtMs, mandateEnvelope, requestorAccount }) {
  return signPaymentRequest({
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
}

/** The operator assembles the descriptor once both signed artifacts exist. */
export function buildDescriptor({ common, mandateEnvelope, requestEnvelope, repositorySha, sessionUuid }) {
  return {
    amountOptions: [common.amount],
    chainId: String(CHAIN_ID),
    expirySeconds: "600",
    mandateDigest: payerMandateDigest(mandateEnvelope),
    namespace: "cbv1",
    payee: { ...common.payee, displayName: "Requestor", role: "payee" },
    payer: { ...common.payer, displayName: "Payer", role: "payer" },
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
}

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

/**
 * Post a message using the next free sequence number.
 *
 * Sequence is per-SESSION and strictly monotonic, not per-role — the relay
 * enforces that so the message order is unambiguous. Two parties therefore share
 * one counter and cannot pick their own numbers independently: read the current
 * high-water mark, take the next one, and retry if the peer beat us to it.
 */
export async function postNext(relay, { relayUrl, sessionId, role, kind, body, keyPair }) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const seen = await relay.pollMessages({ relayUrl, sessionId, after: "0", waitMs: 0 });
    const highest = (seen.messages ?? []).reduce(
      (max, message) => Math.max(max, Number(message.seq)),
      0,
    );
    try {
      return await relay.postMessage({
        relayUrl,
        sessionId,
        envelope: relay.signEnvelope({
          sessionId,
          seq: String(highest + 1),
          role,
          kind,
          body,
          senderKey: keyPair.senderKey,
          privateKeyPem: keyPair.privateKeyPem,
        }),
      });
    } catch (error) {
      // The peer claimed that number between our read and our write. Re-read and
      // take the next one; this is ordinary contention, not a failure.
      if (error?.code !== "SEQ_CONFLICT") throw error;
    }
  }
  stop("FAILED", "Could not find a free position in the session log.");
}
