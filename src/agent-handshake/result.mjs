import {
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";

import { canonicalBytes } from "../core/canonical.mjs";
import {
  AGENT_HANDSHAKE_CHAIN_ID,
  AGENT_HANDSHAKE_REGISTRY_ADDRESS,
  rawAgentOperatorPublicKey,
} from "./descriptor.mjs";

export const AGENT_HANDSHAKE_RESULT_SCHEMA =
  "clockchain.agent-handshake-result/v1";

const RESULT_KEYS = Object.freeze([
  "anchors",
  "externalActionPerformed",
  "issuedAtMs",
  "outcome",
  "parties",
  "reference",
  "schema",
  "sessionDigest",
  "sessionId",
  "statementDigest",
  "subjectRun",
]);
const PARTY_KEYS = Object.freeze([
  "address",
  "agentId",
  "chainId",
  "reference",
  "registryAddress",
]);
const SIGNER_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "publicKey",
  "signature",
]);
const ANCHOR_KEYS = Object.freeze([
  "blockHeight",
  "blockTimeRaw",
  "digest",
  "kind",
  "ledgerId",
]);
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const KINDS = Object.freeze(["proposal", "acceptance", "acknowledgment"]);

export class AgentHandshakeResultError extends Error {
  constructor() {
    super("Agent handshake result verification failed.");
    this.name = "AgentHandshakeResultError";
    this.category = "verification";
    this.code = "AGENT_HANDSHAKE_RESULT_INVALID";
  }
}

function invalid() {
  throw new AgentHandshakeResultError();
}

function exact(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    Object.keys(value).some((key) => !keys.includes(key))
  ) invalid();
  return value;
}

function identityReference(agentId) {
  return `eip155:${AGENT_HANDSHAKE_CHAIN_ID}:${AGENT_HANDSHAKE_REGISTRY_ADDRESS}:${agentId}`;
}

function party(value) {
  exact(value, PARTY_KEYS);
  if (
    !ADDRESS_PATTERN.test(value.address) ||
    !DECIMAL_PATTERN.test(value.agentId) ||
    value.chainId !== AGENT_HANDSHAKE_CHAIN_ID ||
    value.registryAddress !== AGENT_HANDSHAKE_REGISTRY_ADDRESS ||
    value.reference !== identityReference(value.agentId)
  ) invalid();
  return Object.freeze(Object.fromEntries(PARTY_KEYS.map((key) => [key, value[key]])));
}

function anchor(value, index) {
  exact(value, ANCHOR_KEYS);
  if (
    value.kind !== KINDS[index] ||
    !DECIMAL_PATTERN.test(value.blockHeight) ||
    typeof value.blockTimeRaw !== "string" ||
    value.blockTimeRaw.length === 0 ||
    !DIGEST_PATTERN.test(value.digest) ||
    !UUID_PATTERN.test(value.ledgerId)
  ) invalid();
  return Object.freeze(Object.fromEntries(ANCHOR_KEYS.map((key) => [key, value[key]])));
}

function result(value) {
  exact(value, RESULT_KEYS);
  exact(value.parties, ["initiator", "responder"]);
  if (
    value.schema !== AGENT_HANDSHAKE_RESULT_SCHEMA ||
    value.externalActionPerformed !== false ||
    !["VERIFIED", "FAILED"].includes(value.outcome) ||
    !DECIMAL_PATTERN.test(value.issuedAtMs) ||
    typeof value.reference !== "string" ||
    value.reference.length === 0 ||
    !DIGEST_PATTERN.test(value.sessionDigest) ||
    !UUID_PATTERN.test(value.sessionId) ||
    !DIGEST_PATTERN.test(value.statementDigest) ||
    value.subjectRun !== "stakeholder" ||
    !Array.isArray(value.anchors) ||
    value.anchors.length !== 3
  ) invalid();
  const anchors = Object.freeze(value.anchors.map(anchor));
  if (
    BigInt(anchors[0].blockHeight) >= BigInt(anchors[1].blockHeight) ||
    BigInt(anchors[1].blockHeight) >= BigInt(anchors[2].blockHeight)
  ) invalid();
  const initiator = party(value.parties.initiator);
  const responder = party(value.parties.responder);
  if (initiator.address === responder.address || initiator.agentId === responder.agentId) invalid();
  return Object.freeze({
    ...value,
    anchors,
    parties: Object.freeze({ initiator, responder }),
  });
}

function signer(value) {
  exact(value, SIGNER_KEYS);
  if (
    value.algorithm !== "ed25519" ||
    !KEY_ID_PATTERN.test(value.keyId) ||
    typeof value.publicKey !== "string" ||
    Buffer.from(value.publicKey, "base64").length !== 32 ||
    typeof value.signature !== "string" ||
    Buffer.from(value.signature, "base64").length !== 64
  ) invalid();
  return Object.freeze(Object.fromEntries(SIGNER_KEYS.map((key) => [key, value[key]])));
}

function envelope(value) {
  exact(value, ["result", "signer"]);
  return Object.freeze({ result: result(value.result), signer: signer(value.signer) });
}

function publicKeyFromRaw(value) {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({
    format: "der",
    key: Buffer.concat([prefix, Buffer.from(value, "base64")]),
    type: "spki",
  });
}

function sameText(left, right) {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function resultParty(value) {
  return Object.freeze({
    address: value.address,
    agentId: value.agentId,
    chainId: AGENT_HANDSHAKE_CHAIN_ID,
    reference: identityReference(value.agentId),
    registryAddress: AGENT_HANDSHAKE_REGISTRY_ADDRESS,
  });
}

export function buildAgentHandshakeResult({
  issuedAtMs,
  keyId,
  parties,
  privateKeyPem,
  sessionId,
  verdict,
}) {
  let privateKey;
  try {
    privateKey = createPrivateKey(privateKeyPem);
  } catch {
    invalid();
  }
  if (privateKey.asymmetricKeyType !== "ed25519") invalid();
  const certificate = result({
    anchors: verdict.transitions,
    externalActionPerformed: false,
    issuedAtMs: String(issuedAtMs),
    outcome: verdict.outcome,
    parties: {
      initiator: resultParty(parties.initiator),
      responder: resultParty(parties.responder),
    },
    reference: verdict.reference,
    schema: AGENT_HANDSHAKE_RESULT_SCHEMA,
    sessionDigest: verdict.sessionDigest,
    sessionId,
    statementDigest: verdict.statementDigest,
    subjectRun: "stakeholder",
  });
  const publicKey = rawAgentOperatorPublicKey(createPublicKey(privateKey));
  return envelope({
    result: certificate,
    signer: {
      algorithm: "ed25519",
      keyId,
      publicKey,
      signature: sign(null, canonicalBytes(certificate), privateKey).toString("base64"),
    },
  });
}

export function verifyAgentHandshakeResult(value, {
  expectedParty = null,
  expectedPublicKey,
  expectedRole,
  expectedSessionId,
}) {
  const verified = envelope(value);
  if (
    !["initiator", "responder"].includes(expectedRole) ||
    !UUID_PATTERN.test(expectedSessionId) ||
    verified.result.sessionId !== expectedSessionId ||
    verified.result.outcome !== "VERIFIED" ||
    !sameText(verified.signer.publicKey, expectedPublicKey)
  ) invalid();
  if (expectedParty !== null) {
    if (
      verified.result.parties[expectedRole].address !== expectedParty.address ||
      verified.result.parties[expectedRole].agentId !== expectedParty.agentId
    ) invalid();
  }
  let accepted = false;
  try {
    accepted = verify(
      null,
      canonicalBytes(verified.result),
      publicKeyFromRaw(verified.signer.publicKey),
      Buffer.from(verified.signer.signature, "base64"),
    );
  } catch {
    accepted = false;
  }
  if (!accepted) invalid();
  const selected = verified.result.parties[expectedRole];
  return Object.freeze({
    certificateVerified: true,
    externalActionPerformed: false,
    identity: Object.freeze({
      address: selected.address,
      agentId: selected.agentId,
      reference: selected.reference,
    }),
    outcome: verified.result.outcome,
    role: expectedRole,
    sessionId: verified.result.sessionId,
    statementDigest: verified.result.statementDigest,
  });
}
