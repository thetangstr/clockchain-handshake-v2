import { fail } from "./constants.mjs";
import { validateHandshakeV3RoleGrant } from "./validators.mjs";

export function recoverHandshakeV3RoleGrant(grant, options) {
  let current;
  try {
    current = validateHandshakeV3RoleGrant(grant, {
      principalDigest: options.principalDigest,
      proofKeyThumbprint: options.proofKeyThumbprint,
      now: options.now,
    });
  } catch (error) {
    if (error?.code === "ROLE_GRANT_BOUNDARY_MISMATCH") {
      fail("ROLE_GRANT_RECOVERY_DENIED");
    }
    throw error;
  }
  if (!options.roleGrantId || options.roleGrantId === current.roleGrantId) {
    fail("ROLE_GRANT_RECOVERY_DENIED");
  }
  if (current.principalDigest !== options.principalDigest || current.proofKeyThumbprint !== options.proofKeyThumbprint) {
    fail("ROLE_GRANT_RECOVERY_DENIED");
  }
  return validateHandshakeV3RoleGrant({
    ...current,
    roleGrantId: options.roleGrantId,
    recoveredWithoutMutation: true,
    protocolStateMutated: false,
  });
}
