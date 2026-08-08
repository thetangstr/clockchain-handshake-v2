import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { wireReportToAnchor } from "../monitor/anchor.mjs";
import { validateAnchor } from "../monitor/snapshot.mjs";
import { payerMandateDigest } from "../core/payer-mandate.mjs";
import { paymentRequestDigest } from "../core/payment-request.mjs";
import { verifyEnvelope } from "../relay/client.mjs";

export class SessionEnded extends Error {
  constructor(code = "FAILED", message = "The session stopped.") {
    super(message);
    this.name = "SessionEnded";
    this.code = code;
    this.terminalCode = code;
  }
}

const RETRYABLE_EVIDENCE_CODES = new Set([
  "EVIDENCE_NOT_FOUND",
  "RENDEZVOUS_UNAVAILABLE",
  "RATE_BLOCKED",
]);

export function remainingWaitMinutes({ deadline, now }) {
  return Math.round((deadline - now) / 60_000);
}

export function evidenceDeadlineAfterAnchorReport({
  mapped,
  originalDeadlineMs,
  nowMs,
  evidenceAfterReportMs,
}) {
  return mapped ? nowMs + evidenceAfterReportMs : originalDeadlineMs;
}

export async function awaitRoleMessages({
  relayClient,
  relayUrl,
  sessionId,
  kind,
  roles,
  budgetMs,
  waitMs,
  after = "0",
  buffer = [],
  expectedBindings = null,
  now = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  onHeartbeat = async () => {},
  heartbeatMs = 20_000,
}) {
  const wanted = new Set(roles);
  const messages = {};
  const deadline = now() + budgetMs;
  let cursor = after;
  const deferred = [];
  let lastBeat = 0;
  const accept = (message) => {
    if (message?.kind !== kind || !wanted.has(message.role) || messages[message.role] !== undefined) {
      return null;
    }
    if (expectedBindings === null) return message;
    return bindPartyReady(message, expectedBindings[message.role], sessionId);
  };
  const consider = (batch) => {
    for (const message of batch ?? []) {
      if (message?.seq !== undefined && Number(message.seq) > Number(cursor)) {
        cursor = message.seq;
      }
      const accepted = accept(message);
      if (accepted !== null) {
        messages[message.role] = accepted;
      } else {
        deferred.push(message);
      }
    }
  };
  consider(buffer);
  if (roles.every((role) => messages[role] !== undefined)) {
    return { after: cursor, buffer: deferred, messages };
  }
  while (now() < deadline) {
    const got = await relayClient.pollMessages({ relayUrl, sessionId, after: cursor, waitMs });
    consider(got.messages);
    if (roles.every((role) => messages[role] !== undefined)) {
      return { after: cursor, buffer: deferred, messages };
    }
    if (now() - lastBeat > heartbeatMs) {
      lastBeat = now();
      await onHeartbeat({ deadline, messages, now: now() });
    }
    await sleep(Math.min(100, Math.max(0, deadline - now())));
  }
  throw new SessionEnded("EXPIRED", `Timed out waiting for ${kind}.`);
}

function bindPartyReady(message, identityReady, sessionId) {
  const identityAddress = canonicalAddress(identityReady?.body?.address);
  const readyAddress = canonicalAddress(message?.body?.address);
  const agentId = canonicalAgentId(message?.body?.agentId);
  if (
    !isVerifiedEnvelope(identityReady, sessionId) ||
    !isVerifiedEnvelope(message, sessionId) ||
    identityAddress === null ||
    readyAddress !== identityAddress ||
    agentId === null ||
    message?.senderKey !== identityReady?.senderKey
  ) {
    return null;
  }
  return {
    ...message,
    body: {
      ...message.body,
      address: identityAddress,
      agentId,
    },
  };
}

function bindIdentityReady(message, sessionId) {
  const address = canonicalAddress(message?.body?.address);
  if (address === null || !isVerifiedEnvelope(message, sessionId)) return null;
  return {
    ...message,
    body: {
      ...message.body,
      address,
    },
  };
}

function isVerifiedEnvelope(message, sessionId) {
  if (message?.sessionId !== sessionId) return false;
  try {
    return verifyEnvelope(message) === true;
  } catch {
    return false;
  }
}

function canonicalAddress(value) {
  if (typeof value !== "string") return null;
  const address = value.toLowerCase();
  return /^0x[0-9a-f]{40}$/u.test(address) ? address : null;
}

function canonicalAgentId(value) {
  const text = typeof value === "bigint" ? value.toString() : String(value ?? "");
  if (!/^[0-9]+$/u.test(text)) return null;
  return BigInt(text).toString();
}

export async function fundIdentitySeats({
  relayClient,
  relayUrl,
  sessionId,
  roles,
  budgetMs,
  waitMs,
  fundSeat,
  after = "0",
  buffer = [],
  now = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  onHeartbeat = async () => {},
  heartbeatMs = 20_000,
}) {
  const wanted = new Set(roles);
  const messages = {};
  const funded = new Set();
  const deferred = [];
  const deadline = now() + budgetMs;
  let cursor = after;
  let lastBeat = 0;

  const consider = async (batch) => {
    for (const message of batch ?? []) {
      if (message?.seq !== undefined && Number(message.seq) > Number(cursor)) {
        cursor = message.seq;
      }
      const accepted =
        message?.kind === "identity_ready" &&
        wanted.has(message.role) &&
        messages[message.role] === undefined
          ? bindIdentityReady(message, sessionId)
          : null;
      if (accepted !== null) {
        messages[message.role] = accepted;
        if (!funded.has(message.role)) {
          funded.add(message.role);
          await fundSeat({ role: message.role, message: accepted });
        }
      } else {
        deferred.push(message);
      }
    }
  };

  await consider(buffer);
  if (roles.every((role) => messages[role] !== undefined)) {
    return { after: cursor, buffer: deferred, messages };
  }

  while (now() < deadline) {
    const got = await relayClient.pollMessages({ relayUrl, sessionId, after: cursor, waitMs });
    await consider(got.messages);
    if (roles.every((role) => messages[role] !== undefined)) {
      return { after: cursor, buffer: deferred, messages };
    }
    if (now() - lastBeat > heartbeatMs) {
      lastBeat = now();
      await onHeartbeat({ deadline, messages, now: now() });
    }
    await sleep(Math.min(100, Math.max(0, deadline - now())));
  }
  throw new SessionEnded("EXPIRED", "Timed out waiting for identity_ready.");
}

export function mandateBodyFrom(message) {
  const body = message?.body;
  if (!body?.common || !body?.sessionUuid || !body?.mandateEnvelope) {
    throw new SessionEnded("MALFORMED", "The payer mandate message was incomplete.");
  }
  try {
    payerMandateDigest(body.mandateEnvelope);
  } catch {
    throw new SessionEnded("MALFORMED", "The payer mandate message was malformed.");
  }
  return body;
}

export function requestEnvelopeFrom(message) {
  const requestEnvelope = message?.body?.requestEnvelope;
  if (!requestEnvelope) {
    throw new SessionEnded("MALFORMED", "The payment request message was incomplete.");
  }
  try {
    paymentRequestDigest(requestEnvelope);
  } catch {
    throw new SessionEnded("MALFORMED", "The payment request message was malformed.");
  }
  return requestEnvelope;
}

export async function applyAnchorReport({
  message,
  monitorState,
  relayUrl,
  say,
  transitionToAnchor,
}) {
  try {
    if (message?.role !== "payer" || message?.kind !== "anchor_report") return false;
    const reportedTransitions = message.body?.transitions;
    const reportedAnchors = message.body?.anchors;
    const reported = reportedTransitions ?? reportedAnchors;
    const proposal = reported?.proposal;
    const acceptance = reported?.acceptance;
    const acknowledgment = reported?.acknowledgment;
    if (!proposal || !acceptance || !acknowledgment) return false;
    const anchors = reportedTransitions
      ? {
        acceptance: transitionToAnchor("acceptance", acceptance, { relayUrl }),
        acknowledgment: transitionToAnchor("acknowledgment", acknowledgment, { relayUrl }),
        proposal: transitionToAnchor("proposal", proposal, { relayUrl }),
      }
      : {
        acceptance: wireReportToAnchor(acceptance),
        acknowledgment: wireReportToAnchor(acknowledgment),
        proposal: wireReportToAnchor(proposal),
      };
    validateAnchor("proposal", anchors.proposal);
    validateAnchor("acceptance", anchors.acceptance);
    validateAnchor("acknowledgment", anchors.acknowledgment);
    monitorState.anchors = { ...monitorState.anchors, ...anchors };
    await say("PROPOSED", "The payer's proposal is recorded on Clockchain.");
    await say("ACCEPTED", "The requestor accepted the exact terms, and that acceptance is recorded.");
    await say("ACKNOWLEDGED", "All three steps are recorded on Clockchain in order.");
    return true;
  } catch {
    return false;
  }
}

export async function downloadEvidencePackages({
  relayClient,
  relayUrl,
  sessionId,
  root,
  deadlineMs,
  fileSystem = { chmod, mkdir, writeFile },
  now = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  retryPauseMs = 5_000,
  onWaiting = async () => {},
}) {
  const payerDirectory = join(root, "payer");
  const payeeDirectory = join(root, "payee");
  try {
    await fileSystem.mkdir(payerDirectory, { mode: 0o700, recursive: true });
    await fileSystem.mkdir(payeeDirectory, { mode: 0o700, recursive: true });
    await fileSystem.chmod(payerDirectory, 0o700);
    await fileSystem.chmod(payeeDirectory, 0o700);
  } catch (error) {
    throw new SessionEnded("FAILED", `Could not prepare evidence directories: ${error?.code ?? error?.message ?? "unknown"}.`);
  }

  const pending = new Set(["payer", "payee"]);
  const directories = { payer: payerDirectory, payee: payeeDirectory };
  let attempted = false;
  while ((!attempted || now() < deadlineMs) && pending.size > 0) {
    attempted = true;
    for (const role of [...pending]) {
      let parts;
      try {
        parts = await relayClient.getEvidence({ relayUrl, sessionId, role, retryBudgetMs: 0 });
      } catch (error) {
        if (RETRYABLE_EVIDENCE_CODES.has(error?.code)) {
          continue;
        }
        throw error;
      }
      if (!Buffer.isBuffer(parts?.json) || !Buffer.isBuffer(parts?.markdown) || !Buffer.isBuffer(parts?.marker)) {
        throw new SessionEnded("MALFORMED", `The ${role} evidence package was incomplete or malformed.`);
      }
      try {
        await fileSystem.writeFile(join(directories[role], "party-result.json"), parts.json);
        await fileSystem.writeFile(join(directories[role], "PARTY-RESULT.md"), parts.markdown);
        await fileSystem.writeFile(join(directories[role], ".party-result.complete.json"), parts.marker);
      } catch (error) {
        throw new SessionEnded("FAILED", `Could not persist ${role} evidence: ${error?.code ?? error?.message ?? "unknown"}.`);
      }
      pending.delete(role);
    }
    if (pending.size === 0) break;
    if (now() >= deadlineMs) break;
    await onWaiting({ pending: [...pending] });
    await sleep(Math.min(retryPauseMs, Math.max(0, deadlineMs - now())));
  }
  if (pending.size > 0) {
    throw new SessionEnded("MISSING", "Both evidence packages did not arrive in time.");
  }
  return { payeeDirectory, payerDirectory };
}

export async function runHostLoop({
  boot = async () => ({}),
  runOneSession,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  cooldownMs = 2_000,
  onError = () => {},
  maxSessions = Infinity,
}) {
  const bootResult = await boot();
  for (let sessionNumber = 1; sessionNumber <= maxSessions; sessionNumber += 1) {
    try {
      await runOneSession({ bootResult, sessionNumber });
    } catch (error) {
      await onError(error);
      await sleep(cooldownMs);
      continue;
    }
  }
}
