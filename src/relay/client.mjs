// The rendezvous relay's client half -- the outbound side every role uses.
//
// Two behaviours matter more than the rest of the file:
//
//  1. A refused connection or network error is RETRYABLE, never fatal. Every
//     exported call retries with backoff, emitting a heartbeat at least
//     every 30s, for the caller's full wait budget. Only once that budget is
//     exhausted does the call close with the named reason
//     RENDEZVOUS_UNAVAILABLE. This is the single most important behaviour in
//     this file: staggered startup (the relay or the counterparty simply
//     hasn't come up yet) must never be treated as a hard failure.
//  2. Signing and verifying envelopes lives here so no role forgets it.
//     `signEnvelope` produces the envelope; `verifyEnvelope` checks a
//     received one so a role can assert sender identity. The relay itself
//     never checks a signature -- these are the only functions that do.
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";

import { canonicalBytes } from "../core/canonical.mjs";
import {
  publicKeyPemFromRawBase64,
  rawPublicKeyBase64FromPem,
} from "../core/descriptor.mjs";
import { RelayError } from "./errors.mjs";

export { RelayError };

const SEQ_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const ENVELOPE_KEYS = Object.freeze([
  "sessionId",
  "seq",
  "role",
  "kind",
  "body",
  "senderKey",
  "sig",
]);

const DEFAULT_RETRY_BACKOFF_MS = Object.freeze([
  500, 1_000, 2_000, 5_000, 10_000,
]);
const DEFAULT_HEARTBEAT_INTERVAL_MS = 30_000;
export const DEFAULT_RETRY_BUDGET_MS = 30 * 60_000;
const DEFAULT_TIMEOUT_MS = 30_000;

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

// ---------------------------------------------------------------------------
// Envelope signing / verification
// ---------------------------------------------------------------------------

export function generateEnvelopeKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" });
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" });
  return Object.freeze({
    privateKeyPem,
    publicKeyPem,
    senderKey: rawPublicKeyBase64FromPem(publicKeyPem),
  });
}

function privateEd25519KeyFromPem(privateKeyPem) {
  let key;
  try {
    key = createPrivateKey(privateKeyPem);
  } catch {
    throw new RelayError("Invalid Ed25519 private key.", "ENVELOPE_KEY", {
      status: 400,
    });
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new RelayError("Invalid Ed25519 private key.", "ENVELOPE_KEY", {
      status: 400,
    });
  }
  return key;
}

/**
 * Build and sign a message envelope: {sessionId, seq, role, kind, body,
 * senderKey, sig}. `sig` is Ed25519 over the canonical bytes of
 * {sessionId, seq, role, kind, body} -- exactly the shared-contract
 * preimage. `seq` must already be the caller's chosen next sequence number
 * (a decimal string); this function does not consult the relay.
 */
export function signEnvelope({
  sessionId,
  seq,
  role,
  kind,
  body,
  senderKey,
  privateKeyPem,
}) {
  if (
    typeof sessionId !== "string" ||
    sessionId.length === 0 ||
    typeof seq !== "string" ||
    !SEQ_PATTERN.test(seq) ||
    typeof role !== "string" ||
    role.length === 0 ||
    typeof kind !== "string" ||
    kind.length === 0 ||
    typeof senderKey !== "string" ||
    senderKey.length === 0
  ) {
    throw new RelayError("Envelope fields are invalid.", "ENVELOPE_SHAPE", {
      status: 400,
    });
  }
  const preimage = { sessionId, seq, role, kind, body };
  const key = privateEd25519KeyFromPem(privateKeyPem);
  let sig;
  try {
    sig = sign(null, canonicalBytes(preimage), key).toString("base64");
  } catch {
    throw new RelayError("Failed to sign the envelope.", "ENVELOPE_SIGNING", {
      status: 500,
    });
  }
  return Object.freeze({ sessionId, seq, role, kind, body, senderKey, sig });
}

/**
 * Verify a RECEIVED envelope's shape and Ed25519 signature. Throws a
 * RelayError on any failure; returns true on success. The relay never does
 * this -- every role that reads envelopes off the wire must call it.
 */
export function verifyEnvelope(envelope) {
  if (!isPlainObject(envelope)) {
    throw new RelayError("Envelope is not a plain object.", "ENVELOPE_SHAPE", {
      status: 400,
    });
  }
  const keys = Object.keys(envelope);
  if (
    keys.length !== ENVELOPE_KEYS.length ||
    !ENVELOPE_KEYS.every((key) => Object.hasOwn(envelope, key))
  ) {
    throw new RelayError(
      "Envelope does not match the required shape.",
      "ENVELOPE_SHAPE",
      { status: 400 },
    );
  }
  const { sessionId, seq, role, kind, body, senderKey, sig } = envelope;
  if (
    typeof sessionId !== "string" ||
    typeof seq !== "string" ||
    !SEQ_PATTERN.test(seq) ||
    typeof role !== "string" ||
    typeof kind !== "string" ||
    typeof senderKey !== "string" ||
    typeof sig !== "string"
  ) {
    throw new RelayError(
      "Envelope fields have the wrong type.",
      "ENVELOPE_SHAPE",
      { status: 400 },
    );
  }

  let publicKeyPem;
  try {
    publicKeyPem = publicKeyPemFromRawBase64(senderKey);
  } catch {
    throw new RelayError(
      "Envelope sender key is invalid.",
      "ENVELOPE_SENDER_KEY",
      { status: 400 },
    );
  }

  let signatureBytes;
  try {
    signatureBytes = Buffer.from(sig, "base64");
  } catch {
    signatureBytes = null;
  }
  if (
    !signatureBytes ||
    signatureBytes.length !== 64 ||
    signatureBytes.toString("base64") !== sig
  ) {
    throw new RelayError(
      "Envelope signature encoding is invalid.",
      "ENVELOPE_SIGNATURE_ENCODING",
      { status: 400 },
    );
  }

  const preimage = { sessionId, seq, role, kind, body };
  let valid = false;
  try {
    valid = verify(
      null,
      canonicalBytes(preimage),
      createPublicKey(publicKeyPem),
      signatureBytes,
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new RelayError(
      "Envelope signature verification failed.",
      "ENVELOPE_SIGNATURE",
      { status: 400 },
    );
  }
  return true;
}

// ---------------------------------------------------------------------------
// Retry / backoff with heartbeats
// ---------------------------------------------------------------------------

function defaultSleeper(ms) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    if (typeof timer.unref === "function") {
      timer.unref();
    }
  });
}

function defaultMonotonicNow() {
  return Date.now();
}

function isRetryable(error) {
  return (
    error instanceof RelayError &&
    (error.code === "NETWORK_ERROR" || error.code === "SERVER_ERROR")
  );
}

async function withRetry(
  fn,
  {
    budgetMs = DEFAULT_RETRY_BUDGET_MS,
    sleeper = defaultSleeper,
    monotonicNow = defaultMonotonicNow,
    onHeartbeat,
  } = {},
) {
  if (!Number.isFinite(budgetMs) || budgetMs < 0) {
    throw new RelayError("Invalid retry budget.", "MALFORMED", {
      status: 400,
    });
  }
  const startedAt = monotonicNow();
  let attempt = 0;
  let lastHeartbeatAt = startedAt;
  for (;;) {
    try {
      return await fn();
    } catch (error) {
      if (!isRetryable(error)) {
        throw error;
      }
      const now = monotonicNow();
      const elapsedMs = now - startedAt;
      if (elapsedMs >= budgetMs) {
        throw new RelayError(
          "The relay could not be reached within the wait budget.",
          "RENDEZVOUS_UNAVAILABLE",
          { status: 0, detail: { lastError: error.code } },
        );
      }
      const backoff =
        DEFAULT_RETRY_BACKOFF_MS[
          Math.min(attempt, DEFAULT_RETRY_BACKOFF_MS.length - 1)
        ];
      const delay = Math.max(0, Math.min(backoff, budgetMs - elapsedMs));
      attempt += 1;
      await sleeper(delay);
      const after = monotonicNow();
      if (
        onHeartbeat &&
        after - lastHeartbeatAt >= DEFAULT_HEARTBEAT_INTERVAL_MS
      ) {
        onHeartbeat({ elapsedMs: after - startedAt, attempt });
        lastHeartbeatAt = after;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Low-level HTTP
// ---------------------------------------------------------------------------

async function requestJson(method, url, { body, timeoutMs } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(),
    timeoutMs ?? DEFAULT_TIMEOUT_MS,
  );
  if (typeof timer.unref === "function") {
    timer.unref();
  }
  let response;
  try {
    response = await fetch(url, {
      method,
      headers:
        body === undefined ? {} : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (cause) {
    throw new RelayError(
      "The relay could not be reached.",
      "NETWORK_ERROR",
      { status: 0, detail: { cause: cause?.cause?.code ?? cause?.message } },
    );
  } finally {
    clearTimeout(timer);
  }

  const text = await response.text();
  let parsed;
  try {
    parsed = text.length > 0 ? JSON.parse(text) : undefined;
  } catch {
    throw new RelayError(
      "The relay returned a malformed response.",
      "MALFORMED_RESPONSE",
      { status: response.status },
    );
  }

  if (!response.ok) {
    if (response.status === 429) {
      throw new RelayError(
        "The relay is rate-limiting this session.",
        "RATE_BLOCKED",
        { status: 429, detail: parsed?.detail },
      );
    }
    if (response.status >= 500) {
      throw new RelayError(
        "The relay reported an internal error.",
        "SERVER_ERROR",
        { status: response.status, detail: parsed?.detail },
      );
    }
    const code = parsed?.error ?? "RELAY_ERROR";
    throw new RelayError(`Relay request failed: ${code}.`, code, {
      status: response.status,
      detail: parsed?.detail,
    });
  }

  return parsed;
}

function retryOptionsFrom(options) {
  return {
    budgetMs: options.retryBudgetMs,
    sleeper: options.sleeper,
    monotonicNow: options.monotonicNow,
    onHeartbeat: options.onHeartbeat,
  };
}

// ---------------------------------------------------------------------------
// Public client surface
// ---------------------------------------------------------------------------

export async function createSession({
  relayUrl,
  sessionId,
  discovery,
  timeoutMs,
  ...retryOpts
} = {}) {
  return withRetry(
    () =>
      requestJson("POST", `${relayUrl}/v1/sessions`, {
        body: {
          ...(sessionId !== undefined ? { sessionId } : {}),
          ...(discovery !== undefined ? { discovery } : {}),
        },
        timeoutMs,
      }),
    retryOptionsFrom(retryOpts),
  );
}

export async function postMessage({
  relayUrl,
  sessionId,
  envelope,
  timeoutMs,
  ...retryOpts
} = {}) {
  return withRetry(
    () =>
      requestJson(
        "POST",
        `${relayUrl}/v1/sessions/${encodeURIComponent(sessionId)}/messages`,
        { body: envelope, timeoutMs },
      ),
    retryOptionsFrom(retryOpts),
  );
}

export async function pollMessages({
  relayUrl,
  sessionId,
  after = 0,
  waitMs = 25_000,
  timeoutMs,
  ...retryOpts
} = {}) {
  const url = new URL(
    `${relayUrl}/v1/sessions/${encodeURIComponent(sessionId)}/messages`,
  );
  url.searchParams.set("after", String(after));
  url.searchParams.set("waitMs", String(waitMs));
  return withRetry(
    () =>
      requestJson("GET", url.toString(), {
        timeoutMs: timeoutMs ?? waitMs + 10_000,
      }),
    retryOptionsFrom(retryOpts),
  );
}

function toBase64Part(value, part) {
  if (Buffer.isBuffer(value)) {
    return value.toString("base64");
  }
  if (typeof value === "string") {
    return Buffer.from(value, "utf8").toString("base64");
  }
  throw new RelayError(
    `Evidence part "${part}" must be a Buffer or string.`,
    "MALFORMED_EVIDENCE",
    { status: 400 },
  );
}

export async function putEvidence({
  relayUrl,
  sessionId,
  role,
  json,
  markdown,
  marker,
  timeoutMs,
  ...retryOpts
} = {}) {
  const body = {
    json: toBase64Part(json, "json"),
    markdown: toBase64Part(markdown, "markdown"),
    marker: toBase64Part(marker, "marker"),
  };
  return withRetry(
    () =>
      requestJson(
        "PUT",
        `${relayUrl}/v1/sessions/${encodeURIComponent(sessionId)}/evidence/${encodeURIComponent(role)}`,
        { body, timeoutMs },
      ),
    retryOptionsFrom(retryOpts),
  );
}

export async function getEvidence({
  relayUrl,
  sessionId,
  role,
  timeoutMs,
  ...retryOpts
} = {}) {
  const result = await withRetry(
    () =>
      requestJson(
        "GET",
        `${relayUrl}/v1/sessions/${encodeURIComponent(sessionId)}/evidence/${encodeURIComponent(role)}`,
        { timeoutMs },
      ),
    retryOptionsFrom(retryOpts),
  );
  return {
    json: Buffer.from(result.json, "base64"),
    markdown: Buffer.from(result.markdown, "base64"),
    marker: Buffer.from(result.marker, "base64"),
  };
}

export async function getDiscovery({
  relayUrl,
  sessionId,
  timeoutMs,
  ...retryOpts
} = {}) {
  return withRetry(
    () =>
      requestJson(
        "GET",
        `${relayUrl}/v1/discovery/${encodeURIComponent(sessionId)}`,
        { timeoutMs },
      ),
    retryOptionsFrom(retryOpts),
  );
}

export async function getSnapshot({
  relayUrl,
  sessionId,
  timeoutMs,
  ...retryOpts
} = {}) {
  return withRetry(
    () =>
      requestJson(
        "GET",
        `${relayUrl}/v1/sessions/${encodeURIComponent(sessionId)}/snapshot`,
        { timeoutMs },
      ),
    retryOptionsFrom(retryOpts),
  );
}

/**
 * Publish the monitor's handshake snapshot for a session (see
 * src/monitor/snapshot.mjs for the shape). The relay stores whatever it is
 * given, keyed by sessionId -- it does not validate the snapshot shape
 * itself; the caller (an operator process) is expected to have built it with
 * buildSnapshot() so it is already valid.
 */
export async function putSnapshot({
  relayUrl,
  sessionId,
  snapshot,
  timeoutMs,
  ...retryOpts
} = {}) {
  return withRetry(
    () =>
      requestJson(
        "PUT",
        `${relayUrl}/v1/sessions/${encodeURIComponent(sessionId)}/snapshot`,
        { body: snapshot, timeoutMs },
      ),
    retryOptionsFrom(retryOpts),
  );
}

export async function health({ relayUrl, timeoutMs, ...retryOpts } = {}) {
  return withRetry(
    () => requestJson("GET", `${relayUrl}/healthz`, { timeoutMs }),
    retryOptionsFrom(retryOpts),
  );
}

/**
 * Convenience wrapper around the role_claim dance: read the mailbox to see
 * whether the role is already bound, and if not, sign and post a role_claim
 * for it. A role already bound by a (possibly earlier) claim maps to the
 * named reason ROLE_ALREADY_BOUND, per the shared contract. This is
 * advisory on the client's part -- the relay itself does not adjudicate
 * role ownership -- but it is exactly the check every role needs before
 * claiming, so it lives here rather than being reimplemented per role.
 */
export async function claimRole({
  relayUrl,
  sessionId,
  role,
  kind = "role_claim",
  body = {},
  senderKey,
  privateKeyPem,
  maxAttempts = 3,
  ...clientOpts
} = {}) {
  for (let attempt = 1; ; attempt += 1) {
    const { messages } = await pollMessages({
      relayUrl,
      sessionId,
      after: 0,
      waitMs: 0,
      ...clientOpts,
    });
    if (
      messages.some(
        (message) => message.kind === "role_claim" && message.role === role,
      )
    ) {
      throw new RelayError(`Role "${role}" is already bound.`, "ROLE_ALREADY_BOUND", {
        status: 409,
      });
    }
    const seq = String(messages.length + 1);
    const envelope = signEnvelope({
      sessionId,
      seq,
      role,
      kind,
      body,
      senderKey,
      privateKeyPem,
    });
    try {
      const result = await postMessage({
        relayUrl,
        sessionId,
        envelope,
        ...clientOpts,
      });
      return { envelope, result };
    } catch (error) {
      if (
        error instanceof RelayError &&
        error.code === "SEQ_CONFLICT" &&
        attempt < maxAttempts
      ) {
        continue;
      }
      throw error;
    }
  }
}
