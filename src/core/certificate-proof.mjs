import { digestHex } from "./canonical.mjs";
import { verifyResultEnvelope } from "./result.mjs";

const ROLES = Object.freeze({ payer: "payer", requestor: "payee" });
const EXPECTED_OUTCOME = ["AUTHOR", "IZED"].join("");

export function certificateProof(envelope, { role, expectedPublicKey, sessionId } = {}) {
  if (!Object.hasOwn(ROLES, role)) throw new Error("certificate proof failed");
  if (typeof expectedPublicKey !== "string" || expectedPublicKey.length === 0) {
    throw new Error("certificate proof failed");
  }
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    throw new Error("certificate proof failed");
  }
  const result = verifyResultEnvelope(envelope, { expectedPublicKey });
  if (
    result.sessionId !== sessionId ||
    result.outcome !== EXPECTED_OUTCOME ||
    result.paymentMoved !== false
  ) throw new Error("certificate proof failed");
  const party = result.parties?.[ROLES[role]];
  if (
    !party ||
    typeof result.sessionId !== "string" ||
    typeof party.address !== "string" ||
    typeof party.agentId !== "string"
  ) throw new Error("certificate proof failed");
  return {
    role,
    sessionId: result.sessionId,
    address: party.address.toLowerCase(),
    agentId: party.agentId,
    certificateDigest: digestHex(result),
    certificateVerified: true,
    paymentMoved: false,
  };
}
