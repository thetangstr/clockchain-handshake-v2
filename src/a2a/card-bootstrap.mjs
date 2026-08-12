import { types } from "node:util";

import { a2aAgentCardDigest, verifyA2AAgentCard } from "./agent-card.mjs";
import { createDirectTaskChannel } from "./direct-task-channel.mjs";
import { INVITATION_BOOTSTRAP_CARD_CAPABILITY } from "./invitation-bootstrap-transport.mjs";

const ROLES = Object.freeze(["initiator", "responder"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const TOKEN = /^[A-Za-z0-9._:-]{1,128}$/;

function fail() {
  throw new Error("A2A card bootstrap failed safely.");
}

function snapshot(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
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
  } catch (error) {
    if (error?.message === "A2A card bootstrap failed safely.") throw error;
    fail();
  }
}

function optionalSnapshot(value, required, optional = []) {
  try {
    if (
      value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    const allowed = [...required, ...optional];
    if (keys.some((key) => typeof key !== "string" || !allowed.includes(key))) fail();
    for (const key of required) if (!Object.hasOwn(descriptors, key)) fail();
    const result = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail();
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    if (error?.message === "A2A card bootstrap failed safely.") throw error;
    fail();
  }
}

function binding(value) {
  const item = snapshot(value, [
    "endpoint", "partySignerAddress", "runtimeId", "taskId", "workloadAttestationDigest",
  ]);
  if (typeof item.partySignerAddress !== "string" || !ADDRESS.test(item.partySignerAddress)) fail();
  if (typeof item.runtimeId !== "string" || !TOKEN.test(item.runtimeId)) fail();
  if (typeof item.taskId !== "string" || !TOKEN.test(item.taskId)) fail();
  if (typeof item.workloadAttestationDigest !== "string" || !DIGEST.test(item.workloadAttestationDigest)) fail();
  if (typeof item.endpoint !== "string" || !item.endpoint.startsWith("https://") || item.endpoint.length > 256) fail();
  return Object.freeze({ ...item });
}

function runtimeBinding(value) {
  const item = snapshot(value, ["endpoint", "runtimeId", "taskId", "workloadAttestationDigest"]);
  if (typeof item.runtimeId !== "string" || !TOKEN.test(item.runtimeId)) fail();
  if (typeof item.taskId !== "string" || !TOKEN.test(item.taskId)) fail();
  if (typeof item.workloadAttestationDigest !== "string" || !DIGEST.test(item.workloadAttestationDigest)) fail();
  if (typeof item.endpoint !== "string" || !item.endpoint.startsWith("https://") || item.endpoint.length > 256) fail();
  return Object.freeze({ ...item, partySignerAddress: null });
}

function exactCardBinding(card, expected) {
  if (
    (expected.partySignerAddress !== null && card.partySignerAddress !== expected.partySignerAddress) ||
    card.runtimeId !== expected.runtimeId ||
    card.workloadAttestationDigest !== expected.workloadAttestationDigest ||
    card.taskId !== expected.taskId ||
    card.endpoint !== expected.endpoint
  ) fail();
}

function transportCapability(value) {
  try {
    if (
      value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) fail();
    const descriptor = Object.getOwnPropertyDescriptor(value, INVITATION_BOOTSTRAP_CARD_CAPABILITY);
    if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) fail();
    const capability = descriptor.value;
    if (
      capability === null || typeof capability !== "object" || Array.isArray(capability) || types.isProxy(capability) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(capability))
    ) fail();
    const descriptors = Object.getOwnPropertyDescriptors(capability);
    const keys = Reflect.ownKeys(descriptors);
    const expectedKeys = ["registerReceiver", "retire", "sendCard"];
    if (keys.length !== expectedKeys.length || keys.some((key) => typeof key !== "string" || !expectedKeys.includes(key))) fail();
    const result = {};
    for (const key of expectedKeys) {
      const item = descriptors[key];
      if (item?.enumerable !== true || !Object.hasOwn(item, "value") || typeof item.value !== "function") fail();
      result[key] = item.value;
    }
    return Object.freeze(result);
  } catch (error) {
    if (error?.message === "A2A card bootstrap failed safely.") throw error;
    fail();
  }
}

function parseCard(body) {
  if (typeof body !== "string" || body.length === 0 || body.length > 64 * 1024) fail();
  try {
    return JSON.parse(body);
  } catch {
    fail();
  }
}

function opposite(role) {
  if (role === "initiator") return "responder";
  if (role === "responder") return "initiator";
  fail();
}

export function createA2ACardBootstrap(optionsInput) {
  const options = optionalSnapshot(optionsInput, [
    "nowMs", "ownBinding", "peerBinding", "role", "sessionId", "transport",
  ], ["peerRuntime"]);
  if (!ROLES.includes(options.role) || typeof options.sessionId !== "string" || !UUID.test(options.sessionId)) fail();
  if (typeof options.nowMs !== "function") fail();
  const ownBinding = binding(options.ownBinding);
  const peerBinding = options.peerBinding === null
    ? runtimeBinding(options.peerRuntime)
    : binding(options.peerBinding);
  if (peerBinding.partySignerAddress !== null && ownBinding.partySignerAddress === peerBinding.partySignerAddress) fail();
  const capability = transportCapability(options.transport);

  const role = options.role;
  const peerRole = opposite(role);
  const cards = { initiator: null, responder: null };
  const taken = { initiator: false, responder: false };
  const published = { initiator: false, responder: false };
  const seenJtis = new Set();
  const seenNonces = new Set();
  let finalized = false;

  async function validateCard(card, expectedRole, expectedBinding, expectedPeerDigest) {
    let verified;
    try {
      verified = await verifyA2AAgentCard({
        card,
        expectedSessionId: options.sessionId,
        expectedRole,
        expectedPeerCardDigest: expectedPeerDigest,
        nowMs: options.nowMs(),
      });
    } catch {
      fail();
    }
    if (expectedBinding.partySignerAddress === null && verified.partySignerAddress === ownBinding.partySignerAddress) fail();
    if (expectedRole === "responder" && verified.peerCardDigest !== null) fail();
    if (expectedRole === "initiator" && verified.peerCardDigest !== expectedPeerDigest) fail();
    exactCardBinding(verified, expectedBinding);
    if (seenJtis.has(verified.jti) || seenNonces.has(verified.nonce)) fail();
    seenJtis.add(verified.jti);
    seenNonces.add(verified.nonce);
    return verified;
  }

  capability.registerReceiver(async ({ artifactKind, body }) => {
    if (finalized) fail();
    const expectedKind = role === "initiator" ? "responder_card" : "initiator_card";
    if (artifactKind !== expectedKind) fail();
    const expectedRole = peerRole;
    if (cards[expectedRole] !== null) fail();
    if (role === "responder" && cards.responder === null) fail();
    const expectedPeerDigest = expectedRole === "initiator" ? a2aAgentCardDigest(cards.responder) : null;
    const verified = await validateCard(parseCard(body), expectedRole, peerBinding, expectedPeerDigest);
    cards[expectedRole] = verified;
    return a2aAgentCardDigest(verified);
  });

  async function publish(expectedRole, input) {
    if (finalized || role !== expectedRole || published[expectedRole]) fail();
    const item = snapshot(input, ["card", "expiresAtMs"]);
    const now = options.nowMs();
    if (!Number.isSafeInteger(now) || !Number.isSafeInteger(item.expiresAtMs) || item.expiresAtMs <= now) fail();
    if (expectedRole === "initiator" && cards.responder === null) fail();
    const expectedPeerDigest = expectedRole === "initiator" ? a2aAgentCardDigest(cards.responder) : null;
    const verified = await validateCard(item.card, expectedRole, ownBinding, expectedPeerDigest);
    const artifactKind = `${expectedRole}_card`;
    published[expectedRole] = true;
    let result;
    try {
      result = await capability.sendCard({ artifactKind, body: JSON.stringify(verified), expiresAtMs: item.expiresAtMs });
    } catch {
      fail();
    }
    const digest = a2aAgentCardDigest(verified);
    if (result?.acknowledged !== true || result.artifactDigest !== digest) fail();
    cards[expectedRole] = verified;
    return Object.freeze({ cardDigest: digest, acknowledged: true });
  }

  function take(expectedRole) {
    if (finalized || role === expectedRole || cards[expectedRole] === null || taken[expectedRole]) fail();
    taken[expectedRole] = true;
    return cards[expectedRole];
  }

  return Object.freeze({
    publishResponderCard(input) {
      return publish("responder", input);
    },
    takeResponderCard() {
      return take("responder");
    },
    publishInitiatorCard(input) {
      return publish("initiator", input);
    },
    takeInitiatorCard() {
      return take("initiator");
    },
    async verifiedPair() {
      if (finalized || cards.initiator === null || cards.responder === null) fail();
      try {
        await createDirectTaskChannel({
          sessionId: options.sessionId,
          initiatorCard: cards.initiator,
          responderCard: cards.responder,
          nowMs: options.nowMs(),
        });
      } catch {
        fail();
      }
      finalized = true;
      capability.retire();
      return Object.freeze({ initiatorCard: cards.initiator, responderCard: cards.responder });
    },
    publicEvidence() {
      return Object.freeze({
        schema: "clockchain.a2a-card-bootstrap-evidence/v1",
        sessionId: options.sessionId,
        role,
        cardDigests: Object.freeze({
          initiator: cards.initiator === null ? null : a2aAgentCardDigest(cards.initiator),
          responder: cards.responder === null ? null : a2aAgentCardDigest(cards.responder),
        }),
        finalized,
      });
    },
  });
}
