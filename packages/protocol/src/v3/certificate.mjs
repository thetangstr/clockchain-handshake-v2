import { HANDSHAKE_V3_PROTOCOL_VERSION, HANDSHAKE_V3_SCHEMA_VERSION, fail } from "./constants.mjs";
import { handshakeV3Digest } from "./canonical.mjs";
import { compareHandshakeV3DateTime } from "./time.mjs";
import {
  validateHandshakeV3Certificate,
  validateHandshakeV3Continuation,
  validateHandshakeV3ToolResult,
} from "./validators.mjs";

export { validateHandshakeV3Certificate, validateHandshakeV3Continuation } from "./validators.mjs";

export function handshakeV3CertificateSignedProjection(certificate) {
  const valid = validateHandshakeV3Certificate(certificate);
  return Object.freeze({
    certificateId: valid.certificateId,
    sessionId: valid.sessionId,
    policyDigest: valid.policyDigest,
    partyDigests: valid.partyDigests,
    clockchainNetwork: valid.clockchainNetwork,
    trustRootId: valid.trustRootId,
    issuedAt: valid.issuedAt,
    expiresAt: valid.expiresAt,
  });
}

export function handshakeV3ContinuationSignedProjection(continuation) {
  const valid = validateHandshakeV3Continuation(continuation);
  return Object.freeze({
    continuationId: valid.continuationId,
    sessionId: valid.sessionId,
    federationRelationDigest: valid.federationRelationDigest,
    certificateDigest: valid.certificateDigest,
    clockchainNetwork: valid.clockchainNetwork,
    trustRootId: valid.trustRootId,
    partyRoleDigests: valid.partyRoleDigests,
    statementDigest: valid.statementDigest,
    scopeDigest: valid.scopeDigest,
    policyDigest: valid.policyDigest,
    protocolVersion: valid.protocolVersion,
    schemaVersion: valid.schemaVersion,
    issuedAt: valid.issuedAt,
    notBefore: valid.notBefore,
    expiresAt: valid.expiresAt,
    audience: valid.audience,
    allowedNextActionClass: valid.allowedNextActionClass,
    replayNonce: valid.replayNonce,
    revocationHandle: valid.revocationHandle,
  });
}

async function signatureAccepted({ object, signedDigest, issuerSignature, verifyIssuerSignature }) {
  let accepted;
  try {
    accepted = await verifyIssuerSignature({
      signedDigest,
      issuerSignature,
      clockchainNetwork: object.clockchainNetwork,
      trustRootId: object.trustRootId,
    });
  } catch {
    fail("SIGNATURE_INVALID");
  }
  if (accepted !== true) fail("SIGNATURE_INVALID");
  return signedDigest;
}

function certificateSignedDigest(certificate) {
  return handshakeV3Digest(handshakeV3CertificateSignedProjection(certificate));
}

function continuationSignedDigest(continuation) {
  return handshakeV3Digest(handshakeV3ContinuationSignedProjection(continuation));
}

function assertTimeWindow({ issuedAt, notBefore, expiresAt }, now) {
  if (
    compareHandshakeV3DateTime(now, notBefore ?? issuedAt, "RESULT_VERIFICATION_FAILED") < 0 ||
    compareHandshakeV3DateTime(now, expiresAt, "RESULT_VERIFICATION_FAILED") >= 0
  ) {
    fail("RESULT_VERIFICATION_FAILED");
  }
}

function assertSameArray(left, right) {
  return Array.isArray(left) && Array.isArray(right) && left.length === right.length && left.every((value, index) => value === right[index]);
}

async function revocationStatus(getRevocationStatus, handle) {
  let status;
  try {
    status = await getRevocationStatus(handle);
  } catch {
    fail("RESULT_VERIFICATION_FAILED");
  }
  if (status === "GOOD") return "GOOD";
  if (status === "REVOKED") fail("SESSION_REVOKED");
  fail("RESULT_VERIFICATION_FAILED");
}

async function replayRecorded(checkAndRecordReplay, replayNonce, continuationDigest) {
  try {
    return (await checkAndRecordReplay(replayNonce, continuationDigest)) === true;
  } catch {
    fail("RESULT_VERIFICATION_FAILED");
  }
}

export async function verifyHandshakeV3Certificate({
  certificate,
  expectedCertificateDigest,
  expectedPolicyDigest,
  expectedPartyDigests,
  now,
  verifyIssuerSignature,
  getRevocationStatus,
}) {
  const valid = validateHandshakeV3Certificate(certificate);
  const signedDigest = certificateSignedDigest(valid);
  if (valid.certificateDigest !== signedDigest) fail("RESULT_VERIFICATION_FAILED");
  if (expectedCertificateDigest && valid.certificateDigest !== expectedCertificateDigest) fail("RESULT_VERIFICATION_FAILED");
  if (expectedPolicyDigest && valid.policyDigest !== expectedPolicyDigest) fail("POLICY_DIGEST_MISMATCH");
  if (expectedPartyDigests && JSON.stringify(valid.partyDigests) !== JSON.stringify(expectedPartyDigests)) fail("ROLE_DENIED");
  assertTimeWindow(valid, now);
  await signatureAccepted({
    object: valid,
    signedDigest,
    issuerSignature: valid.issuerSignature,
    verifyIssuerSignature,
  });
  const status = await revocationStatus(getRevocationStatus, valid.certificateId);
  return Object.freeze({
    valid: true,
    certificateValid: true,
    continuationValid: false,
    revocationStatus: status,
    checkedAt: now,
    violations: Object.freeze([]),
    externalBusinessActionPerformed: false,
  });
}

export async function verifyHandshakeV3Continuation({
  certificate,
  continuation,
  expectedCertificateDigest,
  expectedPartyRoleDigests,
  expectedStatementDigest,
  expectedScopeDigest,
  expectedPolicyDigest,
  expectedAudience,
  expectedAllowedNextActionClass,
  now,
  verifyIssuerSignature,
  getRevocationStatus,
  checkAndRecordReplay,
}) {
  const validCertificate = validateHandshakeV3Certificate(certificate);
  const validContinuation = validateHandshakeV3Continuation(continuation);
  const certificateDigest = certificateSignedDigest(validCertificate);
  const continuationDigest = continuationSignedDigest(validContinuation);
  if (validCertificate.certificateDigest !== certificateDigest) fail("RESULT_VERIFICATION_FAILED");
  if (
    validContinuation.sessionId !== validCertificate.sessionId ||
    validContinuation.certificateDigest !== validCertificate.certificateDigest ||
    validContinuation.policyDigest !== validCertificate.policyDigest ||
    !assertSameArray(validContinuation.partyRoleDigests, validCertificate.partyDigests) ||
    validContinuation.clockchainNetwork !== validCertificate.clockchainNetwork ||
    validContinuation.trustRootId !== validCertificate.trustRootId
  ) {
    fail("RESULT_VERIFICATION_FAILED");
  }
  if (expectedCertificateDigest && validContinuation.certificateDigest !== expectedCertificateDigest) fail("RESULT_VERIFICATION_FAILED");
  if (expectedPartyRoleDigests && !assertSameArray(validContinuation.partyRoleDigests, expectedPartyRoleDigests)) fail("ROLE_DENIED");
  if (expectedStatementDigest && validContinuation.statementDigest !== expectedStatementDigest) fail("RESULT_VERIFICATION_FAILED");
  if (expectedScopeDigest && validContinuation.scopeDigest !== expectedScopeDigest) fail("RESULT_VERIFICATION_FAILED");
  if (expectedPolicyDigest && validContinuation.policyDigest !== expectedPolicyDigest) fail("POLICY_DIGEST_MISMATCH");
  if (validContinuation.policyDigest !== validCertificate.policyDigest) fail("POLICY_DIGEST_MISMATCH");
  if (validContinuation.protocolVersion !== HANDSHAKE_V3_PROTOCOL_VERSION || validContinuation.schemaVersion !== HANDSHAKE_V3_SCHEMA_VERSION) fail("HANDSHAKE_VERSION_UNSUPPORTED");
  if (expectedAudience && validContinuation.audience !== expectedAudience) fail("RESULT_VERIFICATION_FAILED");
  const allowedNextActionClass = expectedAllowedNextActionClass ?? "A2A_DELIVERY";
  if (validContinuation.allowedNextActionClass !== allowedNextActionClass) fail("RESULT_VERIFICATION_FAILED");
  assertTimeWindow(validCertificate, now);
  assertTimeWindow(validContinuation, now);
  await signatureAccepted({
    object: validCertificate,
    signedDigest: certificateDigest,
    issuerSignature: validCertificate.issuerSignature,
    verifyIssuerSignature,
  });
  await signatureAccepted({
    object: validContinuation,
    signedDigest: continuationDigest,
    issuerSignature: validContinuation.issuerSignature,
    verifyIssuerSignature,
  });
  await revocationStatus(getRevocationStatus, validCertificate.certificateId);
  const status = await revocationStatus(getRevocationStatus, validContinuation.revocationHandle);
  if ((await replayRecorded(checkAndRecordReplay, validContinuation.replayNonce, continuationDigest)) !== true) fail("RESULT_VERIFICATION_FAILED");
  return validateHandshakeV3ToolResult("agent_handshake_result_verify", {
    valid: true,
    certificateValid: true,
    continuationValid: true,
    revocationStatus: status,
    checkedAt: now,
    violations: [],
    externalBusinessActionPerformed: false,
  });
}
