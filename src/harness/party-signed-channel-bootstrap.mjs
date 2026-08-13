import { randomUUID } from "node:crypto";
import { types } from "node:util";

const ERROR = "Party signed channel bootstrap failed safely.";
const ROLES = Object.freeze(["initiator", "responder"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const CARD_POLL_DELAY = 5;
const CARD_RENDEZVOUS_TIMEOUT_MS = 5 * 60_000;
const CARD_CREDENTIAL_LIFETIME_MS = 25_000;
const FAILURES = new WeakMap();

function fail() { throw new Error(ERROR); }
function sanitize(error) { if (error?.message === ERROR) throw error; fail(); }
function stagedFailure(stage) {
  const error = new Error(ERROR);
  FAILURES.set(error, stage);
  return error;
}

export function partySignedChannelBootstrapFailureStage(error) {
  return FAILURES.get(error) ?? null;
}

function exact(value, keys) {
  try {
    if (
      value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const actual = Reflect.ownKeys(descriptors);
    if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail();
    const result = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) { sanitize(error); }
}

function methods(value, names) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const result = {};
    for (const name of names) {
      const descriptor = descriptors[name];
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value") || typeof descriptor.value !== "function") fail();
      result[name] = descriptor.value;
    }
    for (const descriptor of Object.values(descriptors)) if (!Object.hasOwn(descriptor, "value")) fail();
    return Object.freeze(result);
  } catch (error) { sanitize(error); }
}

function defaultSleep() {
  return new Promise((resolve) => setTimeout(resolve, CARD_POLL_DELAY));
}

function cardEvidence(value, sessionId, role) {
  const item = exact(value, ["cardDigests", "finalized", "role", "schema", "sessionId"]);
  const digests = exact(item.cardDigests, ["initiator", "responder"]);
  if (
    item.schema !== "clockchain.a2a-card-bootstrap-evidence/v1" || item.sessionId !== sessionId ||
    item.role !== role || typeof item.finalized !== "boolean"
  ) fail();
  for (const value of Object.values(digests)) if (value !== null && (typeof value !== "string" || !DIGEST.test(value))) fail();
  return Object.freeze({ ...item, cardDigests: Object.freeze({ ...digests }) });
}

export async function activatePartySignedChannel(optionsInput = {}) {
  let failureStage = "input";
  try {
    const options = exact(optionsInput, [
      "createAuthority", "createCardBootstrap", "createTaskTransport", "nowMs", "role", "sessionId", "sleep",
    ]);
    if (
      !ROLES.includes(options.role) || !UUID.test(options.sessionId) ||
      typeof options.createAuthority !== "function" || typeof options.createCardBootstrap !== "function" ||
      typeof options.createTaskTransport !== "function" || typeof options.nowMs !== "function" ||
      typeof options.sleep !== "function"
    ) fail();
    failureStage = "clock";
    const startedAtMs = options.nowMs();
    if (!Number.isSafeInteger(startedAtMs)) fail();
    const rendezvousDeadlineMs = startedAtMs + CARD_RENDEZVOUS_TIMEOUT_MS;
    failureStage = "authority-create";
    const authorityInput = await options.createAuthority();
    failureStage = "authority-methods";
    const authority = methods(authorityInput, [
      "destroy", "publicBinding", "signAcceptanceCheckpoint", "signInitiatorCard", "signProposalCheckpoint", "signResponderCard",
    ]);
    failureStage = "authority-binding";
    const authorityBinding = authority.publicBinding();
    if (authorityBinding?.sessionId !== options.sessionId || authorityBinding?.role !== options.role) fail();
    failureStage = "card-bootstrap-create";
    const bootstrap = methods(await options.createCardBootstrap({ authorityBinding }), [
      "publicEvidence", "publishInitiatorCard", "publishResponderCard", "takeInitiatorCard", "takeResponderCard", "verifiedPair",
    ]);

    function credentialExpiry() {
      const now = options.nowMs();
      if (!Number.isSafeInteger(now) || now >= rendezvousDeadlineMs) fail();
      return now + CARD_CREDENTIAL_LIFETIME_MS;
    }

    async function takePeerCard(peerRole) {
      while (true) {
        const evidence = cardEvidence(bootstrap.publicEvidence(), options.sessionId, options.role);
        if (evidence.cardDigests[peerRole] !== null) {
          return peerRole === "initiator" ? bootstrap.takeInitiatorCard() : bootstrap.takeResponderCard();
        }
        const now = options.nowMs();
        if (!Number.isSafeInteger(now) || now >= rendezvousDeadlineMs) fail();
        await options.sleep();
      }
    }

    if (options.role === "responder") {
      failureStage = "responder-card-sign";
      const expiresAtMs = credentialExpiry();
      const responderCard = await authority.signResponderCard({
        expiresAtMs: String(expiresAtMs),
        jti: `card-${randomUUID()}`,
        nonce: `card-${randomUUID()}`,
      });
      failureStage = "responder-card-publish";
      await bootstrap.publishResponderCard({ card: responderCard, expiresAtMs });
      failureStage = "initiator-card-wait";
      await takePeerCard("initiator");
    } else {
      failureStage = "responder-card-wait";
      const responderCard = await takePeerCard("responder");
      failureStage = "initiator-card-sign";
      const expiresAtMs = credentialExpiry();
      const initiatorCard = await authority.signInitiatorCard({
        expiresAtMs: String(expiresAtMs),
        jti: `card-${randomUUID()}`,
        nonce: `card-${randomUUID()}`,
        responderCard,
      });
      failureStage = "initiator-card-publish";
      await bootstrap.publishInitiatorCard({ card: initiatorCard, expiresAtMs });
    }
    failureStage = "verified-pair";
    const pair = exact(await bootstrap.verifiedPair(), ["initiatorCard", "responderCard"]);
    const cards = Object.freeze({ initiator: pair.initiatorCard, responder: pair.responderCard });
    failureStage = "task-transport";
    const taskTransport = methods(await options.createTaskTransport({ cards, role: options.role }), [
      "close", "publicEvidence", "receive", "sendEnvelope",
    ]);
    return Object.freeze({ authority: authorityInput, cards, taskTransport });
  } catch { throw stagedFailure(failureStage); }
}

export function defaultPartySignedChannelSleep() {
  return defaultSleep();
}
