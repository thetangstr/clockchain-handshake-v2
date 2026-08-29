import {
  HANDSHAKE_V3_CANONICALIZATION,
  HANDSHAKE_V3_DOMAIN_SEPARATOR,
  HANDSHAKE_V3_SIGNING_PAYLOAD_SCHEMA_ID,
  fail,
} from "./constants.mjs";
import { canonicalJsonBytes, handshakeV3Digest } from "./canonical.mjs";
import { validateHandshakeV3SignedAction, validateHandshakeV3SigningRequest } from "./validators.mjs";

export function createHandshakeV3SigningRequest(input) {
  const payload = {
    actionType: input.actionType,
    counterpartyDigest: input.counterpartyDigest ?? null,
    domainSeparator: HANDSHAKE_V3_DOMAIN_SEPARATOR,
    evidenceDigest: input.evidenceDigest ?? null,
    nonce: input.nonce,
    policyDigest: input.policyDigest,
    priorEventDigest: input.priorEventDigest ?? null,
    role: input.role,
    schemaVersion: "3.0.0-draft.1",
    sessionId: input.sessionId,
    signingRequestId: input.signingRequestId,
    stateVersion: input.stateVersion,
    statementDigest: input.statementDigest,
  };
  const canonicalBytes = canonicalJsonBytes(payload);
  return validateHandshakeV3SigningRequest({
    signingRequestId: input.signingRequestId,
    actionType: input.actionType,
    domainSeparator: HANDSHAKE_V3_DOMAIN_SEPARATOR,
    canonicalization: HANDSHAKE_V3_CANONICALIZATION,
    payloadSchemaId: HANDSHAKE_V3_SIGNING_PAYLOAD_SCHEMA_ID,
    sessionId: input.sessionId,
    stateVersion: input.stateVersion,
    role: input.role,
    policyDigest: input.policyDigest,
    statementDigest: input.statementDigest,
    counterpartyDigest: input.counterpartyDigest,
    priorEventDigest: input.priorEventDigest,
    evidenceDigest: input.evidenceDigest,
    nonce: input.nonce,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    canonicalBytesBase64Url: Buffer.from(canonicalBytes).toString("base64url"),
    signingDigest: handshakeV3Digest(payload),
  });
}

export async function verifyHandshakeV3SignedAction({
  request,
  action,
  expectedRole,
  expectedSignerKeyId,
  now,
  verifier,
}) {
  const validRequest = validateHandshakeV3SigningRequest(request);
  const validAction = validateHandshakeV3SignedAction(action);
  if (validRequest.role !== expectedRole) {
    fail("SIGNING_REQUEST_ROLE_MISMATCH");
  }
  if (Date.parse(now) >= Date.parse(validRequest.expiresAt)) {
    fail("SIGNING_REQUEST_EXPIRED");
  }
  if (
    validAction.signingRequestId !== validRequest.signingRequestId ||
    validAction.signingDigest !== validRequest.signingDigest ||
    validAction.signerKeyId !== expectedSignerKeyId
  ) {
    fail("SIGNING_REQUEST_MISMATCH");
  }
  const accepted = await verifier({
    bytes: Buffer.from(validRequest.canonicalBytesBase64Url, "base64url"),
    signature: validAction.signature,
    keyId: validAction.signerKeyId,
    algorithm: validAction.algorithm,
    signingDigest: validAction.signingDigest,
  });
  if (accepted !== true) {
    fail("SIGNATURE_INVALID");
  }
  return Object.freeze({
    verified: true,
    signingRequestId: validRequest.signingRequestId,
    signingDigest: validRequest.signingDigest,
    externalBusinessActionPerformed: false,
  });
}
