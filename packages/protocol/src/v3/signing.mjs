import {
  HANDSHAKE_V3_CANONICALIZATION,
  HANDSHAKE_V3_DOMAIN_SEPARATOR,
  HANDSHAKE_V3_SCHEMA_VERSION,
  HANDSHAKE_V3_SIGNING_PAYLOAD_SCHEMA_ID,
  fail,
} from "./constants.mjs";
import { canonicalJsonBytes, handshakeV3Digest } from "./canonical.mjs";
import { compareHandshakeV3DateTime } from "./time.mjs";
import { validateHandshakeV3Party, validateHandshakeV3SignedAction, validateHandshakeV3SigningRequest } from "./validators.mjs";

export function handshakeV3SigningPayload(input) {
  return Object.freeze({
    actionType: input.actionType,
    counterpartIdentityDigest: input.counterpartIdentityDigest ?? null,
    domainSeparator: HANDSHAKE_V3_DOMAIN_SEPARATOR,
    evidenceDigest: input.evidenceDigest ?? null,
    nonce: input.nonce,
    policyDigest: input.policyDigest,
    priorActionDigest: input.priorActionDigest ?? null,
    role: input.role,
    schemaVersion: HANDSHAKE_V3_SCHEMA_VERSION,
    sessionId: input.sessionId,
    signingRequestId: input.signingRequestId,
    stateVersion: input.stateVersion,
    statementDigest: input.statementDigest,
  });
}

export function createHandshakeV3SigningRequest(input) {
  const payload = handshakeV3SigningPayload(input);
  const canonicalBytes = canonicalJsonBytes(payload);
  const request = {
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
    nonce: input.nonce,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    canonicalBytesBase64Url: Buffer.from(canonicalBytes).toString("base64url"),
    signingDigest: handshakeV3Digest(payload),
  };
  for (const key of ["counterpartIdentityDigest", "priorActionDigest", "evidenceDigest"]) {
    if (input[key] !== undefined) request[key] = input[key];
  }
  return validateHandshakeV3SigningRequest(request);
}

export async function verifyHandshakeV3SignedAction({
  request,
  action,
  expectedParty,
  expectedRole,
  expectedSignerKeyId,
  expectedSigningAlgorithm,
  expectedSigningRequestId,
  expectedSigningDigest,
  now,
  verifier,
}) {
  const validRequest = validateHandshakeV3SigningRequest(request);
  const validAction = validateHandshakeV3SignedAction(action);
  const party = expectedParty ? validateHandshakeV3Party(expectedParty) : null;
  const role = party?.role ?? expectedRole;
  const keyId = party?.signingKeyId ?? expectedSignerKeyId;
  const algorithm = party?.signingAlgorithm ?? expectedSigningAlgorithm;
  if (validRequest.role !== role) fail("ROLE_DENIED");
  if (
    compareHandshakeV3DateTime(now, validRequest.issuedAt, "SIGNATURE_INVALID") < 0 ||
    compareHandshakeV3DateTime(now, validRequest.expiresAt, "SIGNATURE_INVALID") >= 0
  ) {
    fail("SIGNATURE_INVALID");
  }
  const recomputedPayload = handshakeV3SigningPayload(validRequest);
  const recomputedBytesBase64Url = Buffer.from(canonicalJsonBytes(recomputedPayload)).toString("base64url");
  const recomputedDigest = handshakeV3Digest(recomputedPayload);
  if (validRequest.canonicalBytesBase64Url !== recomputedBytesBase64Url || validRequest.signingDigest !== recomputedDigest) {
    fail("SIGNATURE_INVALID");
  }
  if (
    (expectedSigningRequestId && validRequest.signingRequestId !== expectedSigningRequestId) ||
    (expectedSigningDigest && validRequest.signingDigest !== expectedSigningDigest) ||
    validAction.signingRequestId !== validRequest.signingRequestId ||
    validAction.signingDigest !== validRequest.signingDigest ||
    validAction.signerKeyId !== keyId ||
    validAction.algorithm !== algorithm
  ) {
    fail("SIGNATURE_INVALID");
  }
  const accepted = await verifier({
    bytes: Buffer.from(validRequest.canonicalBytesBase64Url, "base64url"),
    signature: validAction.signature,
    keyId: validAction.signerKeyId,
    algorithm: validAction.algorithm,
    publicKey: party?.publicKey,
    signingDigest: validAction.signingDigest,
  });
  if (accepted !== true) fail("SIGNATURE_INVALID");
  return Object.freeze({
    valid: true,
    signingRequestId: validRequest.signingRequestId,
    signingDigest: validRequest.signingDigest,
    externalBusinessActionPerformed: false,
  });
}
