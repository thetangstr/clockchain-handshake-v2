import { randomUUID } from "node:crypto";
import { types } from "node:util";

const ERROR = "Party signed channel bootstrap failed safely.";
const ROLES = Object.freeze(["initiator", "responder"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const MAX_CARD_POLLS = 6_000;
const CARD_POLL_DELAY = 5;

function fail() { throw new Error(ERROR); }
function sanitize(error) { if (error?.message === ERROR) throw error; fail(); }

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
    const now = options.nowMs();
    if (!Number.isSafeInteger(now)) fail();
    const authorityInput = await options.createAuthority();
    const authority = methods(authorityInput, [
      "destroy", "publicBinding", "signAcceptanceCheckpoint", "signInitiatorCard", "signProposalCheckpoint", "signResponderCard",
    ]);
    const authorityBinding = authority.publicBinding();
    if (authorityBinding?.sessionId !== options.sessionId || authorityBinding?.role !== options.role) fail();
    const bootstrap = methods(await options.createCardBootstrap({ authorityBinding }), [
      "publicEvidence", "publishInitiatorCard", "publishResponderCard", "takeInitiatorCard", "takeResponderCard", "verifiedPair",
    ]);
    const expiresAtMs = now + 25_000;

    async function takePeerCard(peerRole) {
      for (let attempt = 0; attempt < MAX_CARD_POLLS; attempt += 1) {
        const evidence = cardEvidence(bootstrap.publicEvidence(), options.sessionId, options.role);
        if (evidence.cardDigests[peerRole] !== null) {
          return peerRole === "initiator" ? bootstrap.takeInitiatorCard() : bootstrap.takeResponderCard();
        }
        await options.sleep();
      }
      fail();
    }

    if (options.role === "responder") {
      const responderCard = await authority.signResponderCard({
        expiresAtMs: String(expiresAtMs),
        jti: `card-${randomUUID()}`,
        nonce: `card-${randomUUID()}`,
      });
      await bootstrap.publishResponderCard({ card: responderCard, expiresAtMs });
      await takePeerCard("initiator");
    } else {
      const responderCard = await takePeerCard("responder");
      const initiatorCard = await authority.signInitiatorCard({
        expiresAtMs: String(expiresAtMs),
        jti: `card-${randomUUID()}`,
        nonce: `card-${randomUUID()}`,
        responderCard,
      });
      await bootstrap.publishInitiatorCard({ card: initiatorCard, expiresAtMs });
    }
    const pair = exact(await bootstrap.verifiedPair(), ["initiatorCard", "responderCard"]);
    const cards = Object.freeze({ initiator: pair.initiatorCard, responder: pair.responderCard });
    const taskTransport = methods(await options.createTaskTransport({ cards, role: options.role }), [
      "close", "publicEvidence", "receive", "sendEnvelope",
    ]);
    return Object.freeze({ authority: authorityInput, cards, taskTransport });
  } catch (error) { sanitize(error); }
}

export function defaultPartySignedChannelSleep() {
  return defaultSleep();
}
