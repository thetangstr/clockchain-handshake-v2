import { recoverMessageAddress } from "viem";
import { createHash } from "node:crypto";
import { types } from "node:util";

import { AGENT_HANDSHAKE_V2_PROTOCOL, AGENT_HANDSHAKE_V2_ROLES } from "./constants.mjs";

export const AGENT_HANDSHAKE_V2_COMMITMENT_CHECKPOINT_SCHEMA = "clockchain.agent-handshake-commitment-checkpoint/v1";

const CHECKPOINT_KEYS = Object.freeze([
  "schema",
  "version",
  "protocol",
  "sessionId",
  "role",
  "artifactType",
  "artifactDigest",
  "sequence",
  "previousCheckpointDigest",
  "issuedAtMs",
  "expiresAtMs",
  "signerAddress",
]);
const SIGNED_CHECKPOINT_KEYS = Object.freeze([...CHECKPOINT_KEYS, "signature"]);
const SIGNATURE_KEYS = Object.freeze(["address", "algorithm", "value"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const EIP191 = /^0x[0-9a-f]{130}$/;
const ARTIFACTS = Object.freeze(["proposal", "counterproposal", "acceptance"]);

export class AgentHandshakeV2CommitmentCheckpointError extends Error {
  constructor() {
    super("Agent handshake v2 commitment checkpoint verification failed.");
    this.name = "AgentHandshakeV2CommitmentCheckpointError";
    this.category = "verification";
    this.code = "AGENT_HANDSHAKE_V2_COMMITMENT_CHECKPOINT_INVALID";
  }
}

function invalid() {
  throw new AgentHandshakeV2CommitmentCheckpointError();
}

function exact(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) invalid();
    const actual = Reflect.ownKeys(value);
    if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) invalid();
    const result = {};
    for (const key of keys) {
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
      result[key] = property.value;
    }
    return result;
  } catch (error) {
    if (error instanceof AgentHandshakeV2CommitmentCheckpointError) throw error;
    invalid();
  }
}

function canonicalize(value, ancestors = new Set(), depth = 0) {
  if (depth > 24) invalid();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.length === 0 || value.length > 512 || value.trim() !== value || !/^[ -~]+$/.test(value)) invalid();
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalid();
    return value;
  }
  if (typeof value !== "object" || Array.isArray(value) || types.isProxy(value) || ancestors.has(value)) invalid();
  if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  ancestors.add(value);
  try {
    const result = {};
    const keys = Reflect.ownKeys(value);
    if (keys.length > 32) invalid();
    for (const key of keys.sort()) {
      if (typeof key !== "string") invalid();
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
      result[key] = canonicalize(property.value, ancestors, depth + 1);
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}

function checkpointBytes(value) {
  return Buffer.from(JSON.stringify(canonicalize(value)), "utf8");
}

function digest(value) {
  return createHash("sha256").update(checkpointBytes(value)).digest("hex");
}

function signature(value) {
  const item = exact(value, SIGNATURE_KEYS);
  if (typeof item.address !== "string" || !ADDRESS.test(item.address) || item.algorithm !== "eip191" || typeof item.value !== "string" || !EIP191.test(item.value)) invalid();
  return Object.freeze(item);
}

function unsignedCheckpoint(value) {
  const item = exact(value, CHECKPOINT_KEYS);
  if (
    item.schema !== AGENT_HANDSHAKE_V2_COMMITMENT_CHECKPOINT_SCHEMA ||
    item.version !== 1 ||
    item.protocol !== AGENT_HANDSHAKE_V2_PROTOCOL ||
    typeof item.sessionId !== "string" ||
    !UUID.test(item.sessionId) ||
    !AGENT_HANDSHAKE_V2_ROLES.includes(item.role) ||
    !ARTIFACTS.includes(item.artifactType) ||
    typeof item.artifactDigest !== "string" ||
    !DIGEST.test(item.artifactDigest) ||
    typeof item.sequence !== "string" ||
    !DECIMAL.test(item.sequence) ||
    BigInt(item.sequence) < 1n ||
    (item.previousCheckpointDigest !== null && (typeof item.previousCheckpointDigest !== "string" || !DIGEST.test(item.previousCheckpointDigest))) ||
    typeof item.issuedAtMs !== "string" ||
    !DECIMAL.test(item.issuedAtMs) ||
    typeof item.expiresAtMs !== "string" ||
    !DECIMAL.test(item.expiresAtMs) ||
    BigInt(item.issuedAtMs) >= BigInt(item.expiresAtMs) ||
    typeof item.signerAddress !== "string" ||
    !ADDRESS.test(item.signerAddress)
  ) invalid();
  return Object.freeze(item);
}

function signedCheckpoint(value) {
  const item = exact(value, SIGNED_CHECKPOINT_KEYS);
  const payload = unsignedCheckpoint(Object.fromEntries(CHECKPOINT_KEYS.map((key) => [key, item[key]])));
  return Object.freeze({ ...payload, signature: signature(item.signature) });
}

export function commitmentCheckpointDigest(value) {
  return digest(signedCheckpoint(value));
}

export async function signAgentHandshakeV2CommitmentCheckpoint({ checkpoint, signMessage }) {
  const payload = unsignedCheckpoint(checkpoint);
  if (typeof signMessage !== "function") invalid();
  let value;
  try {
    value = await signMessage(checkpointBytes(payload));
  } catch {
    invalid();
  }
  return signedCheckpoint({
    ...payload,
    signature: {
      address: payload.signerAddress,
      algorithm: "eip191",
      value,
    },
  });
}

export async function verifyAgentHandshakeV2CommitmentCheckpoint({
  checkpoint,
  expectedSessionId,
  expectedRole,
  expectedSignerAddress,
  expectedArtifactType,
  expectedArtifactDigest,
  expectedSequence,
  expectedPreviousCheckpointDigest,
  nowMs,
}) {
  const verified = signedCheckpoint(checkpoint);
  if (
    verified.sessionId !== expectedSessionId ||
    verified.role !== expectedRole ||
    verified.signerAddress !== expectedSignerAddress ||
    verified.signature.address !== expectedSignerAddress ||
    verified.artifactType !== expectedArtifactType ||
    verified.artifactDigest !== expectedArtifactDigest ||
    verified.sequence !== expectedSequence ||
    verified.previousCheckpointDigest !== expectedPreviousCheckpointDigest ||
    !Number.isSafeInteger(nowMs) ||
    BigInt(nowMs) < BigInt(verified.issuedAtMs) ||
    BigInt(nowMs) >= BigInt(verified.expiresAtMs)
  ) invalid();
  const payload = Object.fromEntries(CHECKPOINT_KEYS.map((key) => [key, verified[key]]));
  let recovered;
  try {
    recovered = (await recoverMessageAddress({
      message: { raw: checkpointBytes(payload) },
      signature: verified.signature.value,
    })).toLowerCase();
  } catch {
    invalid();
  }
  if (recovered !== expectedSignerAddress) invalid();
  return verified;
}

export async function verifyAgentHandshakeV2CommitmentCheckpointChain({
  checkpoints,
  expectedSessionId,
  expectedArtifacts,
  nowMs,
}) {
  if (!Array.isArray(checkpoints) || !Array.isArray(expectedArtifacts) || checkpoints.length !== expectedArtifacts.length || checkpoints.length < 1) invalid();
  let previous = null;
  const verified = [];
  for (let index = 0; index < checkpoints.length; index += 1) {
    const expected = exact(expectedArtifacts[index], ["role", "signerAddress", "artifactType", "artifactDigest"]);
    const sequence = String(index + 1);
    const current = await verifyAgentHandshakeV2CommitmentCheckpoint({
      checkpoint: checkpoints[index],
      expectedSessionId,
      expectedRole: expected.role,
      expectedSignerAddress: expected.signerAddress,
      expectedArtifactType: expected.artifactType,
      expectedArtifactDigest: expected.artifactDigest,
      expectedSequence: sequence,
      expectedPreviousCheckpointDigest: previous === null ? null : commitmentCheckpointDigest(previous),
      nowMs,
    });
    verified.push(current);
    previous = current;
  }
  return Object.freeze(verified);
}

export async function verifyAgentHandshakeV2CommitmentCheckpointPath({
  checkpoints,
  expectedSessionId,
  partySigners,
  terminalArtifacts,
  nowMs,
}) {
  if (!Array.isArray(checkpoints) || checkpoints.length < 2 || checkpoints.length > 16) invalid();
  const signers = exact(partySigners, ["initiator", "responder"]);
  const terminals = exact(terminalArtifacts, ["proposalDigest", "acceptanceDigest"]);
  for (const role of AGENT_HANDSHAKE_V2_ROLES) {
    if (typeof signers[role] !== "string" || !ADDRESS.test(signers[role])) invalid();
  }
  if (typeof terminals.proposalDigest !== "string" || !DIGEST.test(terminals.proposalDigest) || typeof terminals.acceptanceDigest !== "string" || !DIGEST.test(terminals.acceptanceDigest)) invalid();
  let previous = null;
  const verified = [];
  for (let index = 0; index < checkpoints.length; index += 1) {
    const preview = signedCheckpoint(checkpoints[index]);
    const terminalProposal = index === checkpoints.length - 2;
    const terminalAcceptance = index === checkpoints.length - 1;
    if (terminalProposal) {
      if (preview.role !== "initiator" || preview.artifactType !== "proposal" || preview.artifactDigest !== terminals.proposalDigest) invalid();
    } else if (terminalAcceptance) {
      if (preview.role !== "responder" || preview.artifactType !== "acceptance" || preview.artifactDigest !== terminals.acceptanceDigest) invalid();
    } else if (!["proposal", "counterproposal"].includes(preview.artifactType)) {
      invalid();
    }
    const current = await verifyAgentHandshakeV2CommitmentCheckpoint({
      checkpoint: checkpoints[index],
      expectedSessionId,
      expectedRole: preview.role,
      expectedSignerAddress: signers[preview.role],
      expectedArtifactType: preview.artifactType,
      expectedArtifactDigest: preview.artifactDigest,
      expectedSequence: String(index + 1),
      expectedPreviousCheckpointDigest: previous === null ? null : commitmentCheckpointDigest(previous),
      nowMs,
    });
    verified.push(current);
    previous = current;
  }
  return Object.freeze(verified);
}
