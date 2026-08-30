import { fail } from "./constants.mjs";
import { compareHandshakeV3DateTime } from "./time.mjs";
import { parseHandshakeV3Rfc3339ToEpochMilliseconds } from "./time.mjs";
import { validateHandshakeV3RoleGrant, validateHandshakeV3Session } from "./validators.mjs";

export function validateHandshakeV3RoleGrantBinding(grant, context = {}) {
  const valid = validateHandshakeV3RoleGrant(grant);
  if (context.sessionId && valid.sessionId !== context.sessionId) fail("ROLE_DENIED");
  if (context.role && valid.role !== context.role) fail("ROLE_DENIED");
  if (context.principalDigest && valid.principalDigest !== context.principalDigest) fail("PRINCIPAL_DENIED");
  if (context.proofKeyThumbprint && valid.proofKeyThumbprint !== context.proofKeyThumbprint) fail("SENDER_CONSTRAINT_INVALID");
  if (context.tool && !valid.allowedTools.includes(context.tool)) fail("SCOPE_DENIED");
  if (context.now && compareHandshakeV3DateTime(context.now, valid.expiresAt, "TOKEN_EXPIRED") >= 0) fail("TOKEN_EXPIRED");
  return valid;
}

export function recoverHandshakeV3RoleGrant(grant, options) {
  const current = validateHandshakeV3RoleGrantBinding(grant, {
    principalDigest: options.principalDigest,
    proofKeyThumbprint: options.proofKeyThumbprint,
    now: options.now,
  });
  const session = validateHandshakeV3Session(options.session);
  if (!options.roleGrantId || options.roleGrantId === current.roleGrantId) fail("ROLE_DENIED");
  if (session.sessionId !== current.sessionId || session.role !== current.role) fail("ROLE_DENIED");
  return Object.freeze({
    roleGrant: validateHandshakeV3RoleGrant({
      ...current,
      roleGrantId: options.roleGrantId,
    }),
    session,
    recoveredWithoutMutation: true,
  });
}

export function createHandshakeV3RoleGrantRecoveryAuditEvent(invalidatedGrant, replacementGrant, options) {
  const invalidated = validateHandshakeV3RoleGrantBinding(invalidatedGrant);
  const replacement = validateHandshakeV3RoleGrantBinding(replacementGrant, {
    sessionId: invalidated.sessionId,
    role: invalidated.role,
    principalDigest: invalidated.principalDigest,
    proofKeyThumbprint: invalidated.proofKeyThumbprint,
  });
  if (replacement.roleGrantId === invalidated.roleGrantId) fail("ROLE_DENIED");
  parseHandshakeV3Rfc3339ToEpochMilliseconds(options?.occurredAt, "SCHEMA_INVALID");
  return Object.freeze({
    schema: "clockchain.handshake-v3-role-grant-recovery/v1",
    type: "ROLE_GRANT_RECOVERED",
    sessionId: invalidated.sessionId,
    role: invalidated.role,
    invalidatedRoleGrantId: invalidated.roleGrantId,
    replacementRoleGrantId: replacement.roleGrantId,
    principalDigest: invalidated.principalDigest,
    proofKeyThumbprint: invalidated.proofKeyThumbprint,
    occurredAt: options.occurredAt,
  });
}
