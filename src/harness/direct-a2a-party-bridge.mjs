import { createHash, randomUUID } from "node:crypto";
import { types } from "node:util";

import { a2aAgentCardDigest } from "../a2a/agent-card.mjs";
import { A2A_ENVELOPE_SCHEMA, a2aEnvelopeDigest } from "../a2a/envelope.mjs";
import { a2aCanonicalBytes } from "../a2a/auth.mjs";
import { commitmentCheckpointDigest } from "../agent-handshake/v2/commitment-checkpoint.mjs";
import { validateAgentHandshakeV2Party } from "../agent-handshake/v2/party.mjs";
import { validateAgentHandshakeV2Terms } from "../agent-handshake/v2/terms.mjs";
import { decodeSigningBytes } from "../core/wallet-bridge.mjs";
import { digestHex } from "../core/canonical.mjs";
import { PARTY_A2A_ENVELOPE_CAPABILITY } from "./party-a2a-authority.mjs";

const ERROR = "Direct A2A party bridge failed safely.";
const ROLES = Object.freeze(["initiator", "responder"]);
const DIGEST = /^[0-9a-f]{64}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const SHA = /^[0-9a-f]{40}$/;
const ROLE_ACCESS = /^ccra_[A-Za-z0-9_-]{22}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HELPER_SCHEMA = "clockchain.agent-handshake-cli-result/v1";
const REQUEST_SCHEMA = "clockchain.agent-handshake-signing-request/v1";
const MAX_DEPTH = 12;
const MAX_KEYS = 96;
const MAX_ARRAY = 96;
const MAX_STRING = 128 * 1024;
const BRIDGE_FAILURE_STAGES = Object.freeze([
  "input", "tool-name", "clone", "role-access", "session", "invite-shape", "invite-send",
  "accept", "join", "helper", "digest",
]);
const BRIDGE_FAILURES = new WeakMap();

function fail() { throw new Error(ERROR); }
function sanitize(error) { if (error?.message === ERROR) throw error; fail(); }

function stagedBridgeFailure(stage) {
  if (!BRIDGE_FAILURE_STAGES.includes(stage)) fail();
  const error = new Error(ERROR);
  BRIDGE_FAILURES.set(error, stage);
  return error;
}

export function directA2APartyBridgeFailureStage(error) {
  return BRIDGE_FAILURES.get(error) ?? null;
}

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

function publicResultDigest(value) {
  function sorted(item) {
    if (item === null || typeof item !== "object") return item;
    if (Array.isArray(item)) return item.map(sorted);
    const result = {};
    for (const key of Object.keys(item).sort()) result[key] = sorted(item[key]);
    return result;
  }
  return createHash("sha256").update(JSON.stringify(sorted(value))).digest("hex");
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

function payloadFromStep(item) {
  const match = item.shellCommand.match(/--payload-base64url\s+([A-Za-z0-9_-]+)(?:\s|$)/);
  if (match === null) fail();
  const raw = Buffer.from(match[1], "base64url");
  if (raw.length < 1 || raw.toString("base64url") !== match[1]) fail();
  let value;
  try { value = JSON.parse(raw.toString("utf8")); } catch { fail(); }
  return Object.freeze({ raw, value });
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
  if (item.operation === "verify-certificate") {
    const decoded = payloadFromStep(item);
    const payload = snapshot(decoded.value, [
      "certificate", "externalBusinessActionPerformed", "helperVersion", "repositorySha", "role", "schema",
      "sessionDeadlineMs", "sessionId",
    ]);
    if (
      payload.schema !== "clockchain.agent-handshake-certificate-verification/v1" || payload.helperVersion !== "2.1.3" ||
      payload.role !== item.role || payload.sessionId !== item.sessionId || payload.externalBusinessActionPerformed !== false ||
      typeof payload.repositorySha !== "string" || !SHA.test(payload.repositorySha) ||
      typeof payload.sessionDeadlineMs !== "string" || !/^[1-9][0-9]*$/.test(payload.sessionDeadlineMs)
    ) fail();
    const summary = certificateSummary({ certificate: payload.certificate }, item.role, item.sessionId);
    return Object.freeze({
      certificateSummary: summary,
      commandSha256: item.commandSha256,
      direct: false,
      operation: item.operation,
      requestDigest: createHash("sha256").update(decoded.raw).digest("hex"),
      sessionId: item.sessionId,
    });
  }
  if (item.operation !== "sign") {
    return Object.freeze({
      commandSha256: item.commandSha256,
      direct: false,
      operation: item.operation,
      requestDigest: null,
      sessionId: item.sessionId,
    });
  }
  const decoded = payloadFromStep(item);
  const raw = decoded.raw;
  const request = publicClone(decoded.value);
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
      request,
      requestDigest: createHash("sha256").update(raw).digest("hex"),
      sessionId: item.sessionId,
    });
  }
  return Object.freeze({
    commandSha256: item.commandSha256,
    direct: true,
    operation: item.operation,
    request,
    requestDigest: createHash("sha256").update(raw).digest("hex"),
    sessionId: item.sessionId,
  });
}

function helperResult(value, expected) {
  const item = snapshot(value, ["address", "bytesSha256", "helperVersion", "operation", "schema", "signatureHex"]);
  if (
    item.schema !== HELPER_SCHEMA || item.helperVersion !== "2.1.3" || item.operation !== "sign" ||
    !ADDRESS.test(item.address) || !DIGEST.test(item.bytesSha256) || !SIGNATURE.test(item.signatureHex) ||
    item.bytesSha256 !== expected.request.bytesSha256
  ) fail();
  return Object.freeze(item);
}

function certificateResult(value, expectedRole, expectedSessionId) {
  const item = snapshot(value, [
    "certificateVerified", "externalBusinessActionPerformed", "helperVersion", "identity", "operation",
    "outcome", "policyDigest", "role", "schema", "sessionId", "statementDigest",
  ]);
  if (
    item.schema !== HELPER_SCHEMA || item.helperVersion !== "2.1.3" || item.operation !== "verify-certificate" ||
    item.certificateVerified !== true || item.externalBusinessActionPerformed !== false || item.outcome !== "VERIFIED" ||
    item.role !== expectedRole || item.sessionId !== expectedSessionId ||
    !DIGEST.test(item.policyDigest) || !DIGEST.test(item.statementDigest)
  ) fail();
  const identity = publicClone(item.identity);
  return Object.freeze({
    proofDigest: createHash("sha256").update(a2aCanonicalBytes({ ...item, identity })).digest("hex"),
    verified: true,
  });
}

function certificateSummary(value, expectedRole, expectedSessionId) {
  const envelopes = findValues(value, "certificate").filter((entry) => (
    entry !== null && typeof entry === "object" && !Array.isArray(entry) &&
    entry.result !== undefined && entry.signer !== undefined && entry.hostSessionKeyCertificate !== undefined
  ));
  const unique = [...new Set(envelopes.map((entry) => JSON.stringify(entry)))];
  if (unique.length !== 1) fail();
  const envelope = snapshot(publicClone(envelopes[0]), ["hostSessionKeyCertificate", "result", "signer"]);
  const result = snapshot(envelope.result, [
    "anchors", "externalBusinessActionPerformed", "hostSessionKeyCertificateDigest", "identityPolicy", "issuedAtMs",
    "outcome", "parties", "policyDigests", "reference", "schema", "sessionDigest", "sessionId", "statementDigest", "subjectRun",
  ]);
  if (
    result.schema !== "clockchain.agent-handshake-result/v2" || result.sessionId !== expectedSessionId ||
    result.outcome !== "VERIFIED" || result.subjectRun !== "stakeholder" || result.externalBusinessActionPerformed !== false ||
    !Array.isArray(result.anchors) || result.anchors.length !== 3
  ) fail();
  const parties = snapshot(result.parties, ["initiator", "responder"]);
  const identity = validateAgentHandshakeV2Party(parties[expectedRole], { identityPolicy: result.identityPolicy });
  const expectedKinds = ["proposal", "acceptance", "acknowledgment"];
  const anchors = result.anchors.map((entry, index) => {
    const anchor = snapshot(entry, ["blockHeight", "blockTimeRaw", "digest", "kind", "ledgerId"]);
    if (
      anchor.kind !== expectedKinds[index] || typeof anchor.blockHeight !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(anchor.blockHeight) ||
      typeof anchor.ledgerId !== "string" || !UUID.test(anchor.ledgerId) || !DIGEST.test(anchor.digest)
    ) fail();
    return Object.freeze({ blockHeight: anchor.blockHeight, digest: anchor.digest, kind: anchor.kind, ledgerId: anchor.ledgerId });
  });
  return Object.freeze({
    anchors: Object.freeze(anchors),
    certificateDigest: digestHex(envelope),
    resultDigest: digestHex(result),
    identity: publicClone(identity),
  });
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
      "activateSignedChannel", "completionRecorder", "invitationTransport", "nowMs", "role", "sessionId", "submitCheckpoint", "submitSignature",
    ]);
    if (
      !ROLES.includes(options.role) || !(options.sessionId === null || UUID.test(options.sessionId)) || typeof options.nowMs !== "function" ||
      typeof options.activateSignedChannel !== "function" || typeof options.submitCheckpoint !== "function" ||
      typeof options.submitSignature !== "function"
    ) fail();
    const completionRecorder = projectMethods(options.completionRecorder, ["setCompletionHandler"]);
    const invitationTransport = projectMethods(options.invitationTransport, ["publicEvidence", "sendInvitation"]);
    const retained = new Map();
    const deliveries = [];
    const invitations = [];
    let signedChannel = null;
    let signedChannelPromise = null;
    let roleAccess = null;
    let boundSessionId = options.sessionId;
    let activationContext = null;
    let certificate = null;
    let pendingCertificate = null;
    let destroyed = false;

    function active() { if (destroyed) fail(); }
    function bindSession(value) {
      if (!UUID.test(value)) fail();
      if (boundSessionId !== null && boundSessionId !== value) fail();
      boundSessionId = value;
      return value;
    }

    async function activate() {
      active();
      if (boundSessionId === null || activationContext === null) fail();
      if (signedChannelPromise === null) {
        signedChannelPromise = (async () => {
          const activated = snapshot(await options.activateSignedChannel(activationContext), ["authority", "cards", "taskTransport"]);
          const authority = projectMethods(activated.authority, [
            "destroy", "publicBinding", "signAcceptanceCheckpoint", "signInitiatorCard", "signProposalCheckpoint", "signResponderCard",
          ]);
          const signCapability = capability(activated.authority);
          const taskTransport = projectMethods(activated.taskTransport, ["close", "publicEvidence", "receive", "sendEnvelope"]);
          const cardsInput = snapshot(activated.cards, ["initiator", "responder"]);
          const cards = Object.freeze({ initiator: publicClone(cardsInput.initiator), responder: publicClone(cardsInput.responder) });
          const binding = authority.publicBinding();
          if (binding.sessionId !== boundSessionId || binding.role !== options.role) fail();
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
        sessionId: boundSessionId,
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
          completion.role !== options.role || boundSessionId === null || completion.sessionId !== boundSessionId ||
          !DIGEST.test(completion.commandSha256) || !DIGEST.test(completion.requestDigest)
        ) fail();
        const expected = retained.get(completion.commandSha256);
        if (
          expected === undefined || expected.state !== "pending" || expected.operation !== completion.operation ||
          (expected.requestDigest !== null && expected.requestDigest !== completion.requestDigest)
        ) fail();
        expected.state = "active";
        if (expected.direct !== true) {
          if (completion.operation === "verify-certificate") {
            if (certificate !== null || pendingCertificate === null) fail();
            certificate = Object.freeze({
              ...pendingCertificate,
              ...certificateResult(completion.result, options.role, boundSessionId),
            });
            pendingCertificate = null;
          } else if (completion.operation === "sign") {
            const result = helperResult(completion.result, expected);
            if (roleAccess === null) fail();
            const submitted = snapshot(await options.submitSignature({
              access: roleAccess,
              policyDigest: expected.request.policyDigest,
              signatureHex: result.signatureHex,
            }), ["role", "sessionId", "stage"]);
            const expectedStage = expected.request.operation === "identity_claim"
              ? "identity_claimed"
              : `${expected.request.operation}_submitted`;
            if (submitted.role !== options.role || submitted.sessionId !== boundSessionId || submitted.stage !== expectedStage) fail();
          }
          expected.state = "consumed";
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
        if (roleAccess === null) fail();
        const checkpointDigest = commitmentCheckpointDigest(checkpoint);
        const submitted = snapshot(await options.submitCheckpoint({
          access: roleAccess,
          artifactSignatureHex: result.signatureHex,
          checkpoint,
        }), ["checkpointDigest", "role", "sessionId", "stage"]);
        if (
          submitted.checkpointDigest !== checkpointDigest || submitted.role !== options.role ||
          submitted.sessionId !== boundSessionId || submitted.stage !== `${artifactType}_checkpoint_submitted`
        ) fail();
        const signatureSubmitted = snapshot(await options.submitSignature({
          access: roleAccess,
          policyDigest: expected.request.policyDigest,
          signatureHex: result.signatureHex,
        }), ["role", "sessionId", "stage"]);
        if (
          signatureSubmitted.role !== options.role || signatureSubmitted.sessionId !== boundSessionId ||
          signatureSubmitted.stage !== `${artifactType}_submitted`
        ) fail();
        expected.state = "consumed";
        deliveries.push(Object.freeze({
          acknowledged: true,
          artifactDigest: digestHex(signed.envelope),
          artifactType,
          checkpointDigest,
          messageDigests: Object.freeze([first.messageDigest, second.messageDigest]),
        }));
        return Object.freeze({ accepted: true });
      } catch (error) { sanitize(error); }
    }

    const bridge = Object.freeze({
      completionStatus() {
        active();
        return Object.freeze({
          certificatePending: pendingCertificate !== null,
          certificateVerified: certificate !== null,
          complete: boundSessionId !== null && certificate !== null && deliveries.length === 1,
          directDeliveryComplete: deliveries.length === 1,
          protocolSessionId: boundSessionId,
        });
      },
      async observeToolResult(input) {
        let failureStage = "input";
        try {
          active();
          const item = snapshot(input, ["result", "toolName"]);
          failureStage = "tool-name";
          if (typeof item.toolName !== "string" || !item.toolName.startsWith("agent_handshake_")) fail();
          failureStage = "clone";
          const result = publicClone(item.result);
          let digestInput = result;
          failureStage = "role-access";
          const roleAccessValues = findValues(result, "roleAccess").filter((value) => typeof value === "string");
          if (roleAccessValues.length > 0) {
            const unique = [...new Set(roleAccessValues)];
            if (unique.length !== 1 || !ROLE_ACCESS.test(unique[0])) fail();
            if (roleAccess !== null && roleAccess !== unique[0]) fail();
            roleAccess = unique[0];
          }
          failureStage = "session";
          const observedSessionIds = [...new Set(findValues(result, "sessionId").filter((value) => typeof value === "string" && UUID.test(value)))];
          if (boundSessionId !== null && observedSessionIds.some((value) => value !== boundSessionId)) fail();
          if (item.toolName === "agent_handshake_invite") {
            failureStage = "invite-shape";
            if (options.role !== "initiator") fail();
            const invitation = oneValue(result, "responderInvitation", (value) => typeof value === "string" && value.length > 0);
            const sessionId = bindSession(oneValue(result, "sessionId", (value) => typeof value === "string" && UUID.test(value)));
            failureStage = "invite-send";
            const sent = await invitationTransport.sendInvitation({
              invitation,
              sessionId,
              expiresAtMs: options.nowMs() + 30_000,
            });
            if (sent?.acknowledged !== true || !DIGEST.test(sent.invitationDigest)) fail();
            invitations.push(Object.freeze({ acknowledged: true, invitationDigest: sent.invitationDigest }));
          }
          if (item.toolName === "agent_handshake_accept_invitation") {
            failureStage = "accept";
            if (options.role !== "responder") fail();
            const transportEvidence = snapshot(invitationTransport.publicEvidence(), ["sessionId"], [
              "schema", "runId", "role", "peerRole", "localRuntimeId", "peerRuntimeId",
              "localWorkloadAttestationDigest", "peerWorkloadAttestationDigest",
              "localBootstrapPublicKeySha256", "peerBootstrapPublicKeySha256",
              "localCertificateSha256", "peerCertificateSha256", "invitations",
            ]);
            const acceptedSessionId = oneValue(result, "sessionId", (value) => typeof value === "string" && UUID.test(value));
            if (transportEvidence.sessionId !== acceptedSessionId) fail();
            bindSession(acceptedSessionId);
          }
          if (item.toolName === "agent_handshake_join") {
            failureStage = "join";
            const joinedRole = oneValue(result, "role", (value) => value === options.role);
            const sessionId = bindSession(oneValue(result, "sessionId", (value) => typeof value === "string" && UUID.test(value)));
            const repositorySha = oneValue(result, "repositorySha", (value) => typeof value === "string" && SHA.test(value));
            const policyDigest = oneValue(result, "policyDigest", (value) => typeof value === "string" && DIGEST.test(value));
            const termsInput = oneValue(result, "terms", (value) => value !== null && typeof value === "object" && !Array.isArray(value));
            const terms = validateAgentHandshakeV2Terms(publicClone(termsInput));
            if (activationContext !== null) fail();
            activationContext = Object.freeze({ policyDigest, repositorySha, role: joinedRole, sessionId, terms });
            await activate();
          }
          failureStage = "helper";
          const singularSteps = findValues(result, "helperStep").filter((value) => value !== null && typeof value === "object");
          const stepBatches = findValues(result, "helperSteps").filter(Array.isArray);
          if (singularSteps.length > 1 || stepBatches.length > 1 || singularSteps.length + stepBatches.length > 1) fail();
          const steps = singularSteps.length === 1
            ? singularSteps
            : stepBatches.length === 1 ? publicClone(stepBatches[0]) : [];
          if (
            steps.length > 0 && steps.length !== 1 &&
            JSON.stringify(steps.map((step) => step?.operation)) !== JSON.stringify(["init", "policy", "inspect"])
          ) fail();
          for (const step of steps) {
            const expected = signingRequestFromStep(step);
            if (boundSessionId === null || expected.sessionId !== boundSessionId) fail();
            if (expected.direct === true && (expected.request.sessionId !== boundSessionId || expected.request.role !== options.role)) fail();
            if (expected.operation === "verify-certificate") {
              if (item.toolName !== "agent_handshake_get_certificate" || pendingCertificate !== null || certificate !== null) fail();
              pendingCertificate = expected.certificateSummary;
              digestInput = Object.freeze({
                certificateDigest: expected.certificateSummary.certificateDigest,
                commandSha256: expected.commandSha256,
                role: options.role,
                schema: "clockchain.observed-certificate-action/v1",
                sessionId: boundSessionId,
              });
            }
            const prior = retained.get(expected.commandSha256);
            if (
              prior !== undefined &&
              (prior.requestDigest !== expected.requestDigest || prior.operation !== expected.operation || prior.direct !== expected.direct)
            ) fail();
            retained.set(expected.commandSha256, { ...expected, state: prior?.state ?? "pending" });
          }
          failureStage = "digest";
          return Object.freeze({ observed: true, protocolSessionId: boundSessionId, toolResultDigest: publicResultDigest(digestInput) });
        } catch { throw stagedBridgeFailure(failureStage); }
      },
      publicEvidence() {
        active();
        return Object.freeze({
          schema: "clockchain.direct-a2a-party-bridge-evidence/v1",
          sessionId: boundSessionId,
          role: options.role,
          cardDigests: Object.freeze({
            initiator: signedChannel === null ? null : a2aAgentCardDigest(signedChannel.cards.initiator),
            responder: signedChannel === null ? null : a2aAgentCardDigest(signedChannel.cards.responder),
          }),
          cardSignerAddresses: Object.freeze({
            initiator: signedChannel === null ? null : signedChannel.cards.initiator.partySignerAddress,
            responder: signedChannel === null ? null : signedChannel.cards.responder.partySignerAddress,
          }),
          invitations: Object.freeze(invitations.map((entry) => Object.freeze({ ...entry }))),
          deliveries: Object.freeze(deliveries.map((entry) => Object.freeze({ ...entry, messageDigests: Object.freeze([...entry.messageDigests]) }))),
          certificate,
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
