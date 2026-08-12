import { createHash, randomUUID } from "node:crypto";
import { types } from "node:util";

import { a2aAgentCardDigest } from "../a2a/agent-card.mjs";
import { A2A_ENVELOPE_SCHEMA, a2aEnvelopeDigest } from "../a2a/envelope.mjs";
import { a2aCanonicalBytes } from "../a2a/auth.mjs";
import { commitmentCheckpointDigest } from "../agent-handshake/v2/commitment-checkpoint.mjs";
import { decodeSigningBytes } from "../core/wallet-bridge.mjs";
import { digestHex } from "../core/canonical.mjs";
import { PARTY_A2A_ENVELOPE_CAPABILITY } from "./party-a2a-authority.mjs";

const ERROR = "Direct A2A party bridge failed safely.";
const ROLES = Object.freeze(["initiator", "responder"]);
const DIGEST = /^[0-9a-f]{64}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HELPER_SCHEMA = "clockchain.agent-handshake-cli-result/v1";
const REQUEST_SCHEMA = "clockchain.agent-handshake-signing-request/v1";
const MAX_DEPTH = 12;
const MAX_KEYS = 96;
const MAX_ARRAY = 96;
const MAX_STRING = 128 * 1024;

function fail() { throw new Error(ERROR); }
function sanitize(error) { if (error?.message === ERROR) throw error; fail(); }

function snapshot(value, required, optional = []) {
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
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) { sanitize(error); }
}

function publicClone(value, depth = 0) {
  if (depth > MAX_DEPTH) fail();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") { if (value.length > MAX_STRING) fail(); return value; }
  if (typeof value === "number") { if (!Number.isFinite(value)) fail(); return value; }
  if (typeof value !== "object" || types.isProxy(value)) fail();
  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY) fail();
    return value.map((entry) => publicClone(entry, depth + 1));
  }
  if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length > MAX_KEYS || keys.some((key) => typeof key !== "string")) fail();
  const result = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    result[key] = publicClone(descriptor.value, depth + 1);
  }
  return result;
}

function projectMethods(value, keys) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const result = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value") || typeof descriptor.value !== "function") fail();
      result[key] = descriptor.value;
    }
    for (const descriptor of Object.values(descriptors)) {
      if (!Object.hasOwn(descriptor, "value")) fail();
    }
    return Object.freeze(result);
  } catch (error) { sanitize(error); }
}

function capability(authority) {
  try {
    if (authority === null || typeof authority !== "object" || types.isProxy(authority)) fail();
    const descriptor = Object.getOwnPropertyDescriptor(authority, PARTY_A2A_ENVELOPE_CAPABILITY);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) fail();
    return projectMethods(descriptor.value, ["signEnvelope"]);
  } catch (error) { sanitize(error); }
}

function findValues(value, key, found = [], seen = new Set(), depth = 0) {
  if (depth > MAX_DEPTH || value === null || value === undefined) return found;
  if (typeof value === "string") {
    if (value.length > MAX_STRING) fail();
    try { findValues(JSON.parse(value), key, found, seen, depth + 1); } catch {}
    return found;
  }
  if (typeof value !== "object" || types.isProxy(value) || seen.has(value)) return found;
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      if (value.length > MAX_ARRAY) fail();
      for (const entry of value) findValues(entry, key, found, seen, depth + 1);
      return found;
    }
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length > MAX_KEYS || keys.some((entry) => typeof entry !== "string")) fail();
    for (const name of keys) {
      const descriptor = descriptors[name];
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
      if (name === key) found.push(descriptor.value);
      findValues(descriptor.value, key, found, seen, depth + 1);
    }
    return found;
  } finally { seen.delete(value); }
}

function oneValue(value, key, predicate) {
  const values = findValues(value, key).filter(predicate);
  const unique = [...new Set(values.map((entry) => typeof entry === "string" ? entry : JSON.stringify(entry)))];
  if (unique.length !== 1) fail();
  return values[0];
}

function signingRequestFromStep(step) {
  const item = snapshot(step, [
    "approvalCommand", "commandLength", "commandSha256", "operation", "role", "sessionId", "shellCommand",
  ], ["policyDigest"]);
  if (
    !ROLES.includes(item.role) || !UUID.test(item.sessionId) ||
    !DIGEST.test(item.commandSha256) || item.approvalCommand !== `clockchain-agent-authorize ${item.commandSha256}` ||
    typeof item.shellCommand !== "string" || item.commandLength !== Buffer.byteLength(item.shellCommand) ||
    createHash("sha256").update(item.shellCommand).digest("hex") !== item.commandSha256
  ) fail();
  if (item.operation !== "sign") {
    return Object.freeze({
      commandSha256: item.commandSha256,
      direct: false,
      operation: item.operation,
      requestDigest: null,
    });
  }
  const match = item.shellCommand.match(/--payload-base64url\s+([A-Za-z0-9_-]+)(?:\s|$)/);
  if (match === null) fail();
  const raw = Buffer.from(match[1], "base64url");
  if (raw.length < 1 || raw.toString("base64url") !== match[1]) fail();
  let request;
  try { request = JSON.parse(raw.toString("utf8")); } catch { fail(); }
  request = publicClone(request);
  if (
    request.schema !== REQUEST_SCHEMA || typeof request.operation !== "string" || request.operation.length === 0 ||
    request.role !== item.role || request.sessionId !== item.sessionId ||
    !DIGEST.test(request.bytesSha256) || !DIGEST.test(request.policyDigest) ||
    typeof request.bytesGzipBase64Url !== "string"
  ) fail();
  if (!["proposal", "acceptance"].includes(request.operation)) {
    return Object.freeze({
      commandSha256: item.commandSha256,
      direct: false,
      operation: item.operation,
      requestDigest: createHash("sha256").update(raw).digest("hex"),
    });
  }
  return Object.freeze({
    commandSha256: item.commandSha256,
    direct: true,
    operation: item.operation,
    request,
    requestDigest: createHash("sha256").update(raw).digest("hex"),
  });
}

function helperResult(value, expected) {
  const item = snapshot(value, ["address", "bytesSha256", "helperVersion", "operation", "schema", "signatureHex"]);
  if (
    item.schema !== HELPER_SCHEMA || item.helperVersion !== "2.1.2" || item.operation !== "sign" ||
    !ADDRESS.test(item.address) || !DIGEST.test(item.bytesSha256) || !SIGNATURE.test(item.signatureHex) ||
    item.bytesSha256 !== expected.request.bytesSha256
  ) fail();
  return Object.freeze(item);
}

function signedArtifact(request, result) {
  let raw;
  let payload;
  try {
    raw = decodeSigningBytes({ bytesGzipBase64Url: request.bytesGzipBase64Url });
    payload = JSON.parse(raw.toString("utf8"));
  } catch { fail(); }
  if (createHash("sha256").update(raw).digest("hex") !== request.bytesSha256) fail();
  const address = request.operation === "proposal"
    ? payload?.initiator?.sessionKeyAddress
    : payload?.responder?.sessionKeyAddress;
  if (address !== result.address) fail();
  return Object.freeze({
    envelope: Object.freeze({
      schema: `clockchain.agent-handshake-${request.operation}-envelope/v2`,
      payload: publicClone(payload),
      signature: Object.freeze({ address: result.address, algorithm: "eip191", value: result.signatureHex }),
    }),
    artifact: Object.freeze({
      payload: publicClone(payload),
      signature: Object.freeze({ address: result.address, algorithm: "eip191", value: result.signatureHex }),
    }),
  });
}

function checkpointArtifact(checkpoint) {
  const item = publicClone(checkpoint);
  const signature = item.signature;
  if (signature === null || typeof signature !== "object") fail();
  const payload = { ...item };
  delete payload.signature;
  return Object.freeze({ payload: Object.freeze(payload), signature: Object.freeze(signature) });
}

function envelopeInput({ artifact, artifactType, cards, expiresAtMs, nonce, previousMessageDigest, role, sequence, sessionId }) {
  return Object.freeze({
    schema: A2A_ENVELOPE_SCHEMA,
    version: 1,
    sessionId,
    fromCardDigest: a2aAgentCardDigest(cards[role]),
    toCardDigest: a2aAgentCardDigest(cards[role === "initiator" ? "responder" : "initiator"]),
    sequence,
    artifactType,
    artifactDigest: a2aEnvelopeDigest({ artifact }),
    previousMessageDigest,
    expiresAtMs,
    nonce,
    body: artifact,
    ciphertext: null,
  });
}

function reconstructInbound(message, schema) {
  if (message?.body?.payload?.schema !== schema || message.body.signature === undefined) fail();
  return Object.freeze({
    schema: schema.replace(/\/(v\d+)$/, "-envelope/$1"),
    payload: publicClone(message.body.payload),
    signature: publicClone(message.body.signature),
  });
}

export function createDirectA2APartyBridge(optionsInput = {}) {
  try {
    const options = snapshot(optionsInput, [
      "activateSignedChannel", "completionRecorder", "invitationTransport", "nowMs", "role", "sessionId",
    ]);
    if (
      !ROLES.includes(options.role) || !UUID.test(options.sessionId) || typeof options.nowMs !== "function" ||
      typeof options.activateSignedChannel !== "function"
    ) fail();
    const completionRecorder = projectMethods(options.completionRecorder, ["setCompletionHandler"]);
    const invitationTransport = projectMethods(options.invitationTransport, ["sendInvitation"]);
    const retained = new Map();
    const deliveries = [];
    const invitations = [];
    let signedChannel = null;
    let signedChannelPromise = null;
    let destroyed = false;

    function active() { if (destroyed) fail(); }

    async function activate() {
      active();
      if (signedChannelPromise === null) {
        signedChannelPromise = (async () => {
          const activated = snapshot(await options.activateSignedChannel(), ["authority", "cards", "taskTransport"]);
          const authority = projectMethods(activated.authority, [
            "destroy", "publicBinding", "signAcceptanceCheckpoint", "signInitiatorCard", "signProposalCheckpoint", "signResponderCard",
          ]);
          const signCapability = capability(activated.authority);
          const taskTransport = projectMethods(activated.taskTransport, ["close", "publicEvidence", "receive", "sendEnvelope"]);
          const cardsInput = snapshot(activated.cards, ["initiator", "responder"]);
          const cards = Object.freeze({ initiator: publicClone(cardsInput.initiator), responder: publicClone(cardsInput.responder) });
          const binding = authority.publicBinding();
          if (binding.sessionId !== options.sessionId || binding.role !== options.role) fail();
          signedChannel = Object.freeze({ authority, cards, signCapability, taskTransport });
          return signedChannel;
        })();
      }
      return await signedChannelPromise;
    }

    async function sendArtifact({ artifact, artifactType, expiresAtMs, previousMessageDigest, sequence }) {
      const { cards, signCapability, taskTransport } = await activate();
      const now = options.nowMs();
      const deliveryExpiry = Math.min(
        Number(expiresAtMs),
        Number(cards.initiator.expiresAtMs),
        Number(cards.responder.expiresAtMs),
      );
      if (!Number.isSafeInteger(now) || !Number.isSafeInteger(deliveryExpiry) || now >= deliveryExpiry) fail();
      const input = envelopeInput({
        artifact,
        artifactType,
        cards,
        expiresAtMs: String(deliveryExpiry),
        nonce: `message-${randomUUID()}`,
        previousMessageDigest,
        role: options.role,
        sequence,
        sessionId: options.sessionId,
      });
      const envelope = await signCapability.signEnvelope({
        envelope: input,
        fromCard: cards[options.role],
        toCard: cards[options.role === "initiator" ? "responder" : "initiator"],
      });
      const sent = await taskTransport.sendEnvelope({ envelope });
      if (typeof sent?.messageDigest !== "string" || !DIGEST.test(sent.messageDigest)) fail();
      return Object.freeze({ messageDigest: sent.messageDigest, artifactDigest: input.artifactDigest });
    }

    async function takeProposalContext() {
      const { taskTransport } = await activate();
      const first = await taskTransport.receive();
      const second = await taskTransport.receive();
      if (first === null || second === null || first.artifactType !== "proposal" || second.artifactType !== "proposal") fail();
      const proposalEnvelope = reconstructInbound(first, "clockchain.agent-handshake-proposal/v2");
      if (second.body?.payload?.schema !== "clockchain.agent-handshake-commitment-checkpoint/v1") fail();
      const proposalCheckpoint = Object.freeze({ ...publicClone(second.body.payload), signature: publicClone(second.body.signature) });
      return Object.freeze({ proposalEnvelope, proposalCheckpoint });
    }

    async function handleCompletion(input) {
      try {
        active();
        const completion = snapshot(input, [
          "actionId", "commandSha256", "operation", "requestDigest", "result", "role", "sessionId",
        ]);
        if (
          typeof completion.operation !== "string" || completion.operation.length === 0 ||
          completion.role !== options.role || completion.sessionId !== options.sessionId ||
          !DIGEST.test(completion.commandSha256) || !DIGEST.test(completion.requestDigest)
        ) fail();
        const expected = retained.get(completion.commandSha256);
        if (
          expected === undefined || expected.state !== "pending" || expected.operation !== completion.operation ||
          (expected.requestDigest !== null && expected.requestDigest !== completion.requestDigest)
        ) fail();
        expected.state = "active";
        if (expected.direct !== true) {
          expected.state = "consumed";
          if (completion.operation === "init") void activate().catch(() => {});
          return Object.freeze({ accepted: true });
        }
        if (completion.operation !== "sign") fail();
        const result = helperResult(completion.result, expected);
        const signed = signedArtifact(expected.request, result);
        const artifactType = expected.request.operation;
        let proposalContext = null;
        if (artifactType === "acceptance") proposalContext = await takeProposalContext();
        const { authority } = await activate();
        const checkpoint = artifactType === "proposal"
          ? await authority.signProposalCheckpoint({ proposalEnvelope: signed.envelope })
          : await authority.signAcceptanceCheckpoint({
              acceptanceEnvelope: signed.envelope,
              proposalCheckpoint: proposalContext.proposalCheckpoint,
              proposalEnvelope: proposalContext.proposalEnvelope,
            });
        const first = await sendArtifact({
          artifact: signed.artifact,
          artifactType,
          expiresAtMs: signed.envelope.payload.expiresAtMs,
          previousMessageDigest: null,
          sequence: "1",
        });
        const second = await sendArtifact({
          artifact: checkpointArtifact(checkpoint),
          artifactType,
          expiresAtMs: checkpoint.expiresAtMs,
          previousMessageDigest: first.messageDigest,
          sequence: "2",
        });
        expected.state = "consumed";
        deliveries.push(Object.freeze({
          acknowledged: true,
          artifactDigest: digestHex(signed.envelope),
          artifactType,
          checkpointDigest: commitmentCheckpointDigest(checkpoint),
          messageDigests: Object.freeze([first.messageDigest, second.messageDigest]),
        }));
        return Object.freeze({ accepted: true });
      } catch (error) { sanitize(error); }
    }

    const bridge = Object.freeze({
      async observeToolResult(input) {
        try {
          active();
          const item = snapshot(input, ["result", "toolName"]);
          if (typeof item.toolName !== "string" || !item.toolName.startsWith("agent_handshake_")) fail();
          const result = publicClone(item.result);
          if (item.toolName === "agent_handshake_invite") {
            if (options.role !== "initiator") fail();
            const invitation = oneValue(result, "responderInvitation", (value) => typeof value === "string" && value.length > 0);
            const sent = await invitationTransport.sendInvitation({
              invitation,
              sessionId: options.sessionId,
              expiresAtMs: options.nowMs() + 30_000,
            });
            if (sent?.acknowledged !== true || !DIGEST.test(sent.invitationDigest)) fail();
            invitations.push(Object.freeze({ acknowledged: true, invitationDigest: sent.invitationDigest }));
          }
          const steps = findValues(result, "helperStep").filter((value) => value !== null && typeof value === "object");
          if (steps.length > 1) fail();
          if (steps.length === 1) {
            const expected = signingRequestFromStep(steps[0]);
            if (expected.direct === true && (expected.request.sessionId !== options.sessionId || expected.request.role !== options.role)) fail();
            const prior = retained.get(expected.commandSha256);
            if (
              prior !== undefined &&
              (prior.requestDigest !== expected.requestDigest || prior.operation !== expected.operation || prior.direct !== expected.direct)
            ) fail();
            retained.set(expected.commandSha256, { ...expected, state: prior?.state ?? "pending" });
          }
          return Object.freeze({ observed: true, toolResultDigest: createHash("sha256").update(a2aCanonicalBytes(result)).digest("hex") });
        } catch (error) { sanitize(error); }
      },
      publicEvidence() {
        active();
        return Object.freeze({
          schema: "clockchain.direct-a2a-party-bridge-evidence/v1",
          sessionId: options.sessionId,
          role: options.role,
          cardDigests: Object.freeze({
            initiator: signedChannel === null ? null : a2aAgentCardDigest(signedChannel.cards.initiator),
            responder: signedChannel === null ? null : a2aAgentCardDigest(signedChannel.cards.responder),
          }),
          invitations: Object.freeze(invitations.map((entry) => Object.freeze({ ...entry }))),
          deliveries: Object.freeze(deliveries.map((entry) => Object.freeze({ ...entry, messageDigests: Object.freeze([...entry.messageDigests]) }))),
        });
      },
      async destroy() {
        try {
          destroyed = true;
          retained.clear();
          if (signedChannelPromise !== null) {
            try { await signedChannelPromise; } catch {}
          }
          if (signedChannel !== null) {
            const results = await Promise.allSettled([
              () => signedChannel.taskTransport.close(),
              () => signedChannel.authority.destroy(),
            ].map((teardown) => Promise.resolve().then(teardown)));
            if (results.some((result) => result.status === "rejected")) fail();
          }
          return Object.freeze({ destroyed: true });
        } catch (error) { sanitize(error); }
      },
    });
    completionRecorder.setCompletionHandler(handleCompletion);
    return bridge;
  } catch (error) { sanitize(error); }
}
