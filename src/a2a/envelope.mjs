import { recoverMessageAddress } from "viem";

import { canonicalBytes } from "../core/canonical.mjs";
import {
  A2A_ARTIFACTS,
  assertAddress,
  assertDecimal,
  assertDigest,
  assertToken,
  assertWindow,
  addressFromPublicKey,
  digest,
  exact,
  invalid,
  recoverSigner,
  signPayload,
  signature,
} from "./auth.mjs";
import { a2aAgentCardDigest } from "./agent-card.mjs";

export const A2A_ENVELOPE_SCHEMA = "clockchain.a2a-envelope/v1";
const ENVELOPE_KEYS = Object.freeze([
  "schema",
  "version",
  "sessionId",
  "fromCardDigest",
  "toCardDigest",
  "sequence",
  "artifactType",
  "artifactDigest",
  "previousMessageDigest",
  "expiresAtMs",
  "nonce",
  "body",
  "ciphertext",
]);
const SIGNED_ENVELOPE_KEYS = Object.freeze([...ENVELOPE_KEYS, "signature"]);

function artifactSignature(value) {
  const item = exact(value, ["payload", "signature"]);
  const proof = signature(item.signature);
  return Object.freeze({ payload: item.payload, signature: proof });
}

async function assertSignedArtifact({ body, expectedAddress, expectedDigest }) {
  const artifact = artifactSignature(body);
  assertAddress(expectedAddress);
  if (artifact.signature.address !== expectedAddress) invalid();
  if (digest({ artifact }) !== expectedDigest) invalid();
  let recovered;
  try {
    recovered = (await recoverMessageAddress({
      message: { raw: canonicalBytes(artifact.payload) },
      signature: artifact.signature.value,
    })).toLowerCase();
  } catch {
    invalid();
  }
  if (recovered !== expectedAddress) invalid();
  return artifact;
}

function unsignedEnvelope(value) {
  const item = exact(value, ENVELOPE_KEYS);
  if (item.schema !== A2A_ENVELOPE_SCHEMA || item.version !== 1) invalid();
  if (typeof item.sessionId !== "string" || item.sessionId.length === 0) invalid();
  assertDigest(item.fromCardDigest);
  assertDigest(item.toCardDigest);
  assertDecimal(item.sequence);
  if (!A2A_ARTIFACTS.includes(item.artifactType)) invalid();
  assertDigest(item.artifactDigest);
  if (item.previousMessageDigest !== null) assertDigest(item.previousMessageDigest);
  assertDecimal(item.expiresAtMs);
  assertToken(item.nonce);
  if (item.ciphertext !== null && (typeof item.ciphertext !== "string" || item.ciphertext.length === 0 || item.ciphertext.length > 4096)) invalid();
  if (item.body === null && item.ciphertext === null) invalid();
  return Object.freeze(item);
}

function signedEnvelope(value) {
  const item = exact(value, SIGNED_ENVELOPE_KEYS);
  const payload = unsignedEnvelope(Object.fromEntries(ENVELOPE_KEYS.map((key) => [key, item[key]])));
  return Object.freeze({ ...payload, signature: signature(item.signature) });
}

export function a2aEnvelopeDigest(value) {
  return digest(value);
}

export async function signA2AEnvelope({ envelope, fromCard, toCard, signMessage }) {
  const payload = unsignedEnvelope(envelope);
  if (payload.fromCardDigest !== a2aAgentCardDigest(fromCard) || payload.toCardDigest !== a2aAgentCardDigest(toCard)) invalid();
  const signatureValue = await signPayload({ payload, signerAddress: addressFromPublicKey(fromCard.a2aCardPublicKey), signMessage });
  return signedEnvelope({ ...payload, signature: signatureValue });
}

export async function verifyA2AEnvelope({ envelope, fromCard, toCard, nowMs }) {
  const verified = signedEnvelope(envelope);
  if (
    verified.sessionId !== fromCard.sessionId ||
    verified.sessionId !== toCard.sessionId ||
    verified.fromCardDigest !== a2aAgentCardDigest(fromCard) ||
    verified.toCardDigest !== a2aAgentCardDigest(toCard) ||
    verified.signature.address !== addressFromPublicKey(fromCard.a2aCardPublicKey)
  ) invalid();
  assertWindow({ issuedAtMs: fromCard.issuedAtMs, expiresAtMs: verified.expiresAtMs, nowMs });
  const payload = Object.fromEntries(ENVELOPE_KEYS.map((key) => [key, verified[key]]));
  if (await recoverSigner(payload, verified.signature.value) !== addressFromPublicKey(fromCard.a2aCardPublicKey)) invalid();
  if (verified.body !== null) {
    await assertSignedArtifact({
      body: verified.body,
      expectedAddress: fromCard.partySignerAddress,
      expectedDigest: verified.artifactDigest,
    });
  }
  return verified;
}
