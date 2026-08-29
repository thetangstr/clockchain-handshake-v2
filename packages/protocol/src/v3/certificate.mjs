import { fail } from "./constants.mjs";
import { handshakeV3Digest } from "./canonical.mjs";
import { assertDigest, assertIsoDate, assertString, cloneStrictRecord, deepFreeze } from "./validators.mjs";

function validateSignature(signature) {
  const value = cloneStrictRecord(signature, ["keyId", "algorithm", "signature"], ["keyId", "algorithm", "signature"]);
  assertString(value.keyId);
  assertString(value.algorithm);
  assertString(value.signature);
  return deepFreeze(value);
}

export function validateHandshakeV3Certificate(value) {
  const certificate = cloneStrictRecord(value, [
    "certificateId",
    "schemaVersion",
    "sessionId",
    "statementDigest",
    "policyDigest",
    "scopeDigest",
    "parties",
    "issuedAt",
    "expiresAt",
    "clockchainAnchorDigest",
    "clockchainSignature",
  ], [
    "certificateId",
    "schemaVersion",
    "sessionId",
    "statementDigest",
    "policyDigest",
    "scopeDigest",
    "parties",
    "issuedAt",
    "expiresAt",
    "clockchainAnchorDigest",
    "clockchainSignature",
  ]);
  for (const key of ["certificateId", "schemaVersion", "sessionId"]) assertString(certificate[key]);
  for (const key of ["statementDigest", "policyDigest", "scopeDigest", "clockchainAnchorDigest"]) assertDigest(certificate[key]);
  if (!Array.isArray(certificate.parties) || certificate.parties.length !== 2) fail("SCHEMA_INVALID");
  certificate.parties = certificate.parties.map((party) => {
    const valid = cloneStrictRecord(party, ["role", "partyDigest", "signingKeyId"], ["role", "partyDigest", "signingKeyId"]);
    assertString(valid.role);
    assertDigest(valid.partyDigest);
    assertString(valid.signingKeyId);
    return deepFreeze(valid);
  });
  assertIsoDate(certificate.issuedAt);
  assertIsoDate(certificate.expiresAt);
  certificate.clockchainSignature = validateSignature(certificate.clockchainSignature);
  return deepFreeze(certificate);
}

export function validateHandshakeV3Continuation(value) {
  const continuation = cloneStrictRecord(value, [
    "continuationId",
    "certificateId",
    "sessionId",
    "statementDigest",
    "policyDigest",
    "scopeDigest",
    "audience",
    "actionClass",
    "notBefore",
    "expiresAt",
    "replayNonce",
    "clockchainSignature",
  ], [
    "continuationId",
    "certificateId",
    "sessionId",
    "statementDigest",
    "policyDigest",
    "scopeDigest",
    "audience",
    "actionClass",
    "notBefore",
    "expiresAt",
    "replayNonce",
    "clockchainSignature",
  ]);
  for (const key of ["continuationId", "certificateId", "sessionId", "audience", "actionClass", "replayNonce"]) assertString(continuation[key]);
  for (const key of ["statementDigest", "policyDigest", "scopeDigest"]) assertDigest(continuation[key]);
  assertIsoDate(continuation.notBefore);
  assertIsoDate(continuation.expiresAt);
  continuation.clockchainSignature = validateSignature(continuation.clockchainSignature);
  return deepFreeze(continuation);
}

async function requireGoodRevocationStatus(getRevocationStatus, objectId) {
  const status = await getRevocationStatus(objectId);
  if (status === "UNKNOWN") {
    fail("REVOCATION_STATUS_UNKNOWN");
  }
  if (status !== "GOOD") {
    fail("OBJECT_REVOKED");
  }
}

export async function verifyHandshakeV3Certificate({
  certificate,
  expectedSessionId,
  expectedStatementDigest,
  expectedPolicyDigest,
  expectedScopeDigest,
  now,
  verifyClockchainSignature,
  getRevocationStatus,
}) {
  const valid = validateHandshakeV3Certificate(certificate);
  if (
    valid.sessionId !== expectedSessionId ||
    valid.statementDigest !== expectedStatementDigest ||
    valid.policyDigest !== expectedPolicyDigest ||
    valid.scopeDigest !== expectedScopeDigest
  ) {
    fail("CERTIFICATE_BINDING_MISMATCH");
  }
  const nowMs = Date.parse(now);
  if (nowMs < Date.parse(valid.issuedAt)) fail("CERTIFICATE_NOT_YET_VALID");
  if (nowMs >= Date.parse(valid.expiresAt)) fail("CERTIFICATE_EXPIRED");
  await requireGoodRevocationStatus(getRevocationStatus, valid.certificateId);
  const signedDigest = handshakeV3Digest({
    certificateId: valid.certificateId,
    sessionId: valid.sessionId,
    statementDigest: valid.statementDigest,
    policyDigest: valid.policyDigest,
    scopeDigest: valid.scopeDigest,
    parties: valid.parties,
    issuedAt: valid.issuedAt,
    expiresAt: valid.expiresAt,
    clockchainAnchorDigest: valid.clockchainAnchorDigest,
  });
  const accepted = await verifyClockchainSignature({ signedDigest, signature: valid.clockchainSignature });
  if (accepted !== true) fail("SIGNATURE_INVALID");
  return Object.freeze({ verified: true, certificateId: valid.certificateId, certificateDigest: signedDigest, externalBusinessActionPerformed: false, safeStop: true });
}

export async function verifyHandshakeV3Continuation({
  certificate,
  continuation,
  expectedAudience,
  expectedActionClass,
  now,
  verifyClockchainSignature,
  getRevocationStatus,
  checkAndRecordReplay,
}) {
  const validCertificate = validateHandshakeV3Certificate(certificate);
  const validContinuation = validateHandshakeV3Continuation(continuation);
  if (
    validContinuation.certificateId !== validCertificate.certificateId ||
    validContinuation.sessionId !== validCertificate.sessionId ||
    validContinuation.statementDigest !== validCertificate.statementDigest ||
    validContinuation.policyDigest !== validCertificate.policyDigest ||
    validContinuation.scopeDigest !== validCertificate.scopeDigest ||
    validContinuation.audience !== expectedAudience ||
    validContinuation.actionClass !== expectedActionClass
  ) {
    fail("CONTINUATION_BINDING_MISMATCH");
  }
  const nowMs = Date.parse(now);
  if (nowMs < Date.parse(validContinuation.notBefore)) fail("CONTINUATION_NOT_YET_VALID");
  if (nowMs >= Date.parse(validContinuation.expiresAt)) fail("CONTINUATION_EXPIRED");
  await requireGoodRevocationStatus(getRevocationStatus, validContinuation.continuationId);
  if ((await checkAndRecordReplay(validContinuation.replayNonce)) !== true) {
    fail("CONTINUATION_REPLAYED");
  }
  const signedDigest = handshakeV3Digest({
    continuationId: validContinuation.continuationId,
    certificateId: validContinuation.certificateId,
    sessionId: validContinuation.sessionId,
    statementDigest: validContinuation.statementDigest,
    policyDigest: validContinuation.policyDigest,
    scopeDigest: validContinuation.scopeDigest,
    audience: validContinuation.audience,
    actionClass: validContinuation.actionClass,
    notBefore: validContinuation.notBefore,
    expiresAt: validContinuation.expiresAt,
    replayNonce: validContinuation.replayNonce,
  });
  const accepted = await verifyClockchainSignature({ signedDigest, signature: validContinuation.clockchainSignature });
  if (accepted !== true) fail("SIGNATURE_INVALID");
  return Object.freeze({ verified: true, continuationId: validContinuation.continuationId, continuationDigest: signedDigest, externalBusinessActionPerformed: false, safeStop: true });
}
