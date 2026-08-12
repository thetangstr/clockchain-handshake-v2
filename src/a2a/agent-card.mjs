import {
  A2A_ROLES,
  assertArtifacts,
  assertAddress,
  assertDigest,
  assertPublicKey,
  assertToken,
  assertUrl,
  assertWindow,
  digest,
  exact,
  invalid,
  recoverSigner,
  signPayload,
  signature,
} from "./auth.mjs";

export const A2A_AGENT_CARD_SCHEMA = "clockchain.a2a-agent-card/v1";
const CARD_KEYS = Object.freeze([
  "schema",
  "version",
  "sessionId",
  "role",
  "partySignerAddress",
  "partySignerPublicKey",
  "a2aCardPublicKey",
  "workloadAttestationDigest",
  "runtimeId",
  "taskId",
  "endpoint",
  "peerCardDigest",
  "issuedAtMs",
  "expiresAtMs",
  "nonce",
  "jti",
  "supportedArtifacts",
]);
const SIGNED_CARD_KEYS = Object.freeze([...CARD_KEYS, "signature"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function unsignedCard(value) {
  const item = exact(value, CARD_KEYS);
  if (item.schema !== A2A_AGENT_CARD_SCHEMA || item.version !== 1) invalid();
  if (typeof item.sessionId !== "string" || !UUID.test(item.sessionId) || !A2A_ROLES.includes(item.role)) invalid();
  assertAddress(item.partySignerAddress);
  assertPublicKey(item.partySignerPublicKey);
  assertPublicKey(item.a2aCardPublicKey);
  assertDigest(item.workloadAttestationDigest);
  assertToken(item.runtimeId);
  assertToken(item.taskId);
  assertUrl(item.endpoint);
  if (item.peerCardDigest !== null) assertDigest(item.peerCardDigest);
  assertWindow(item);
  assertToken(item.nonce);
  assertToken(item.jti);
  return Object.freeze({
    ...item,
    supportedArtifacts: assertArtifacts(item.supportedArtifacts),
  });
}

export function validateUnsignedA2AAgentCard(value) {
  return unsignedCard(value);
}

function signedCard(value) {
  const item = exact(value, SIGNED_CARD_KEYS);
  const payload = unsignedCard(Object.fromEntries(CARD_KEYS.map((key) => [key, item[key]])));
  return Object.freeze({ ...payload, signature: signature(item.signature) });
}

export async function signA2AAgentCard({ card, signMessage }) {
  const payload = unsignedCard(card);
  return signedCard({
    ...payload,
    signature: await signPayload({ payload, signerAddress: payload.partySignerAddress, signMessage }),
  });
}

export function a2aAgentCardDigest(card) {
  return digest(signedCard(card));
}

export async function verifyA2AAgentCard({
  card,
  expectedSessionId,
  expectedRole,
  expectedPeerCardDigest = null,
  nowMs,
  seenJtis = null,
}) {
  const verified = signedCard(card);
  if (
    verified.sessionId !== expectedSessionId ||
    verified.role !== expectedRole ||
    (expectedPeerCardDigest !== null && verified.peerCardDigest !== expectedPeerCardDigest) ||
    verified.signature.address !== verified.partySignerAddress
  ) invalid();
  assertWindow({ issuedAtMs: verified.issuedAtMs, expiresAtMs: verified.expiresAtMs, nowMs });
  if (seenJtis?.has(verified.jti)) invalid();
  const payload = Object.fromEntries(CARD_KEYS.map((key) => [key, verified[key]]));
  if (await recoverSigner(payload, verified.signature.value) !== verified.partySignerAddress) invalid();
  return verified;
}
